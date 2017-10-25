"""
Copyright 2017-present, Airbnb Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from abc import ABCMeta, abstractmethod, abstractproperty
from decimal import Decimal
import json
import time
from timeit import timeit

import boto3
from botocore.exceptions import ClientError
import requests

from app_integrations import LOGGER
from app_integrations.batcher import Batcher
from app_integrations.exceptions import AppIntegrationException, AppIntegrationConfigError

STREAMALERT_APPS = {}


def app(subclass):
    """Class decorator to register all AppIntegration classes.

    This should be applied to any subclass for the AppIntegration as '@app'

    Args:
        subclass (AppIntegration): The subclass of AppIntegration that should
            be stored within the STREAMALERT_APPS mapping
    """
    STREAMALERT_APPS[subclass.type()] = subclass
    return subclass


def get_app(config, init=True):
    """Return the proper app integration for this service

    Args:
        config (AppConfig): Loaded configuration with service, etc

    Returns:
        AppIntegration: Subclass of AppIntegration
    """
    try:
        if not init:
            return STREAMALERT_APPS[config['type']]

        return STREAMALERT_APPS[config['type']](config)
    except KeyError:
        if 'type' not in config:
            raise AppIntegrationException('The \'type\' is not defined in the config.')
        else:
            raise AppIntegrationException('App integration does not exist for type: '
                                          '{}'.format(config['type']))


class AppIntegration(object):
    """Base class for all app integrations to be implemented for various services"""
    __metaclass__ = ABCMeta
    # This _POLL_BUFFER_MULTIPLIER is a multiplier that will be used, along with the time it
    # took to perform an API request and forward logs, to determine if there is enough
    # time remaining in the execution of this function to perform another request.
    # The buffer is also to account for any finalization that must occur, like config
    # saving to parameter store and spawning a new Lambda invocation if there are more
    # logs to poll for this interval
    _POLL_BUFFER_MULTIPLIER = 1.5

    def __init__(self, config):
        self._config = config
        self._batcher = Batcher(config)
        self._gathered_log_count = 0
        self._more_to_poll = False
        self._poll_count = 0
        self._last_timestamp = 0

    @classmethod
    @abstractproperty
    def service(cls):
        """Get this log's origin service

        This should be implemented by all subclasses.

        Examples: 'duo', 'google', 'onelogin', 'box', etc

        Returns:
            str: The originating service name for these logs.
        """

    @classmethod
    @abstractproperty
    def _type(cls):
        """Get the specific type of log for this app

        This should be implemented by all subclasses.

        Returns:
            str: The specific type of log (auth, admin, events etc)
        """

    @classmethod
    def type(cls):
        """Returns a combination of the service and log type

        Returns:
            str: The specific type of log (duo_auth, duo_admin, google_admin, etc)
        """
        return '_'.join([cls.service(), cls._type()])

    @abstractmethod
    def required_auth_info(self):
        """Get the expected info that this service's auth dictionary should contain.

        This should be implemented by subclasses and provide context as to what authentication
        information is required as well as a description of the data and an optional regex
        that the data should conform to.

        Returns:
            dict: Required authentication keys, with optional description and
                format they should follow
        """

    @abstractmethod
    def _gather_logs(self):
        """Get gathered logs from the service

        This should be implemented by all subclasses.

        Returns:
            list or bool: The list of logs fetched from the service, or False if
                there was an error during log collection.
        """

    @abstractmethod
    def _sleep_seconds(self):
        """Get the amount of time this service should sleep before performing another poll.

        This should be implemented by all subclasses and is necessary by some services
        to avoid overloading the API with requests.

        Returns:
            int: Number of seconds the polling function should sleep for
        """

    @classmethod
    def date_formatter(cls):
        """Returns a format string to assist in formatting dates for this service

        Returns:
            str: A format string for formatting date/time values (ie: '%Y-%m-%dT%H:%M:%SZ')
        """

    def _sleep(self):
        """Function to sleep the looping"""
        # Do not sleep if this is the first poll
        if self._poll_count == 0:
            LOGGER.debug('Skipping sleep for first poll')
            return

        # Sleep for n seconds so the called API does not return a bad response
        sleep_for_secs = self._sleep_seconds()
        LOGGER.debug('Sleeping \'%s\' app for %d seconds...', self.type(), sleep_for_secs)

        time.sleep(sleep_for_secs)

    def _initialize(self):
        """Method for performing any startup steps, like setting state to running"""
        # Perform another safety check to make sure this is not being invoked already
        if self._config.is_running:
            LOGGER.error('App already running for service \'%s\'.', self.type())
            return False

        # Check if this is an invocation spawned from a previous partial execution
        # Return if the config is marked as 'partial' but the invocation type is wrong
        if not self._config.is_successive_invocation and self._config.is_partial:
            LOGGER.error('App in partial execution state for service \'%s\'.', self.type())
            return False

        LOGGER.info('App starting for service \'%s\'.', self.type())

        LOGGER.info('App executing as a successive invocation: %s',
                    self._config.is_successive_invocation)

        # Validate the auth in the config. This raises an exception upon failure
        self._validate_auth()

        self._last_timestamp = self._config.last_timestamp

        # Mark this app as running, which updates the parameter store
        self._config.mark_running()

        return True

    def _finalize(self):
        """Method for performing any final steps, like saving applicable state

        This function is also used to invoke a new copy of this lambda in the case
        that there are more logs available to collect.
        """
        if not self._last_timestamp:
            LOGGER.error('Ending last timestamp is 0. This should not happen and is likely '
                         'due to the subclass not setting this value.')

        if self._last_timestamp == self._config.start_last_timestamp:
            LOGGER.error('Ending last timestamp is the same as the beginning last timestamp. '
                         'This could occur if there were no logs collected for this execution.')

        LOGGER.info('App complete for service \'%s\'. Gathered %d logs in %d polls.',
                    self.type(), self._gathered_log_count, self._poll_count)

        self._config.last_timestamp = self._last_timestamp

        # If there are more logs to poll, invoke this app function again and mark
        # the config as 'partial'. Marking the state as 'partial' prevents
        # scheduled function invocations from running alongside chained invocations.
        if self._more_to_poll:
            self._invoke_successive_gather()

            self._config.mark_partial()
            return

        self._config.mark_success()

    def _invoke_successive_gather(self):
        """Invoke a successive app function to handle more logs

        This is useful when there were more logs to collect than could be accomplished
        in this execution. Instead of marking the config with 'success' and waiting
        for the next scheduled execution, this will invoke the lambda again with an
        'event' indicating there are more logs to collect. Other scheduled executions
        will not have an 'event' to allow for this type of override, and will exit
        when checking the 'self._config.is_running' property. This allows for chained
        invocations without the worry of duplicated effort or collisions.
        """
        try:
            lambda_client = boto3.client('lambda', region_name=self._config['region'])
            response = lambda_client.invoke(
                FunctionName=self._config['function_name'],
                InvocationType='Event',
                Payload=json.dumps({'invocation_type': self._config.Events.SUCCESSIVE_INVOKE}),
                Qualifier=self._config['qualifier']
            )
        except ClientError as err:
            LOGGER.error('An error occurred while invoking a subsequent app function '
                         '(\'%s:%s\'). Error is: %s',
                         self._config['function_name'],
                         self._config['qualifier'],
                         err.response)
            raise

        LOGGER.info('Invoking successive apps function \'%s\' with Lambda request ID \'%s\'',
                    self._config['function_name'],
                    response['ResponseMetadata']['RequestId'])

    def _check_http_response(self, response):
        """Method for checking for a valid HTTP response code

        Returns:
            bool: Indicator of whether or not this request was successful
        """
        success = response is not None and (200 <= response.status_code <= 299)

        if response is not None and not success:
            LOGGER.error('HTTP request failed for service \'%s\': [%d] %s',
                         self.type(),
                         response.status_code,
                         response.json()['message'])

        return success

    def _make_get_request(self, full_url, headers, params=None):
        """Method for returning the json loaded response for this GET request

        Returns:
            tuple (bool, dict): False if the was an error performing the request,
                and the dictionary loaded from the json response
        """
        LOGGER.debug('Making GET request for service \'%s\' on poll #%d',
                     self.type(), self._poll_count)

        # Perform the request and return the response as a dict
        response = requests.get(full_url, headers=headers, params=params)

        return self._check_http_response(response), response.json()

    def _make_post_request(self, full_url, headers, data):
        """Method for returning the json loaded response for this POST request

        Returns:
            tuple (bool, dict): False if the was an error performing the request,
                and the dictionary loaded from the json response
        """
        LOGGER.debug('Making POST request for service \'%s\' on poll #%d',
                     self.type(), self._poll_count)

        # Perform the request and return the response as a dict
        response = requests.post(full_url, headers=headers, json=data)

        return self._check_http_response(response), response.json()

    def _validate_auth(self):
        """Method for validating the authentication dictionary retrieved from
        AWS Parameter Store

        Returns:
            bool: Indicator of successful validation
        """
        if not self._config:
            raise AppIntegrationConfigError('Config for service \'{}\' is empty', self.type())

        # The config validates that the 'auth' dict was loaded, but do a safety check here
        if not 'auth' in self._config:
            raise AppIntegrationConfigError('Auth config for service \'{}\' is empty', self.type())

        # Get the required authentication keys from the info returned by the subclass
        required_keys = set(self.required_auth_info())
        auth_key_diff = required_keys.difference(set(self._config['auth']))
        if not auth_key_diff:
            return

        missing_auth_keys = ', '.join('\'{}\''.format(key) for key in auth_key_diff)
        raise AppIntegrationConfigError('Auth config for service \'{}\' is missing the following '
                                        'required keys: {}'.format(self.type(), missing_auth_keys))

    def _gather(self):
        """Protected entry point for the beginning of polling"""

        # Make this request sleep if the API throttles requests
        self._sleep()
        def do_gather():
            """Perform the gather using this scoped method so we can time it"""
            # Increment the poll count
            self._poll_count += 1

            logs = self._gather_logs()

            # Make sure there are logs, this can be False if there was an issue polling
            # of if there are no new logs to be polled
            if not logs:
                LOGGER.error('Gather process for service \'%s\' was not able to poll any logs '
                             'on poll #%d', self.type(), self._poll_count)
                return

            # Increment the count of logs gathered
            self._gathered_log_count += len(logs)

            # Utilize the batcher to send logs to the rule processor
            self._batcher.send_logs(self._config['function_name'], logs)

            LOGGER.debug('Updating config last timestamp from %s to %s',
                         self._config.last_timestamp, self._last_timestamp)

            # Save the config's last timestamp after each function run
            self._config.last_timestamp = self._last_timestamp

        # Use timeit to track how long one poll takes, and cast to a decimal.
        # Use decimal since these floating point values can be very small and the
        # builtin float uses scientific notation when handling very small values
        exec_time = Decimal(timeit(do_gather, number=1))

        LOGGER.info('Gather process for \'%s\' executed in %f seconds.', self.type(), exec_time)

        # Add a 50% buffer to the time it took to account for some unforeseen delay and to give
        # this function enough time to spawn a new invocation if there are more logs to poll
        # Cast this back to float so general arithemtic works
        return float(exec_time * Decimal(self._POLL_BUFFER_MULTIPLIER))

    def gather(self):
        """Public method for actual gathering of logs"""
        # Initialize, saving state to 'running'
        if not self._initialize():
            return

        while self._gather() + self._sleep_seconds() < self._config.remaining_ms() / 1000.0:
            LOGGER.debug('More logs to poll for \'%s\': %s', self.type(), self._more_to_poll)
            self._config.report_remaining_seconds()
            if not self._more_to_poll:
                break

            # Reset the boolean indicating that there is more data to poll. Subclasses should
            # set this to 'True' within their implementation of the '_gather_logs' function
            self._more_to_poll = not self._more_to_poll

        LOGGER.debug('Gathered all logs possible for this execution. More logs to poll '
                     'for \'%s\': %s', self.type(), self._more_to_poll)

        self._config.report_remaining_seconds()

        # Finalize, saving state to 'succeeded'
        self._finalize()

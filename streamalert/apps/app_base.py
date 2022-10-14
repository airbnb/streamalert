"""
Copyright 2017-present Airbnb, Inc.

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
import time
from abc import ABCMeta, abstractmethod , abstractproperty
from json import JSONDecodeError

import boto3
import requests
from botocore.exceptions import ClientError

from streamalert.apps.batcher import Batcher
from streamalert.apps.config import AppConfig
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


def _report_time(func):
    """Decorator that returns the time the wrapped function took to run

    This should not be applied to functions where the return value is needed by the caller

    Returns:
        float: time, in seconds, for which the wrapped function ran
    """
    def _wrapper(*args, **kwargs):
        start = time.time()
        func(*args, **kwargs)
        total = time.time() - start
        LOGGER.info('[%s] Function executed in %.4f seconds.', func.__name__, total)
        return total

    return _wrapper


def safe_timeout(func):
    """Try/Except decorator to catch any timeout error raised by requests

    Args:
        func (im_func): Function wrapper for safety catching requests that
            could result in a connection or read timeout.
    """
    def _wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.Timeout:
            LOGGER.exception('[%s] Request timed out', func.__name__)
            return False, None

    return _wrapper


class AppIntegration(metaclass=ABCMeta):
    """Base class for all app integrations to be implemented for various services"""
    # This _POLL_BUFFER_MULTIPLIER is a multiplier that will be used, along with the time it
    # took to perform an API request and forward logs, to determine if there is enough
    # time remaining in the execution of this function to perform another request.
    # The buffer is also to account for any finalization that must occur, like config
    # saving to parameter store and spawning a new Lambda invocation if there are more
    # logs to poll for this interval
    _POLL_BUFFER_MULTIPLIER = 1.5
    # _DEFAULT_REQUEST_TIMEOUT indicates how long the requests library will wait before timing
    # out for both get and post requests. This applies to both connection and read timeouts
    _DEFAULT_REQUEST_TIMEOUT = 3.05
    # _EOF_SECONDS_BUFFER is the end-of-function padding in seconds needed to handle cleanup, etc
    _EOF_SECONDS_BUFFER = 2

    def __init__(self, event, context):
        self._config = AppConfig.load_config(event, context)
        self._batcher = Batcher(self._config.function_name, self._config.destination_function)
        self._gathered_log_count = 0
        self._more_to_poll = False
        self._poll_count = 0
        self._last_timestamp = 0
        self._context = {}

    def __str__(self):
        return self.type()

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
        return '_'.join([cls.service(), cls._type()]) # pylint: disable=no-value-for-parameter

    @classmethod
    def required_auth_info(cls):
        """Public method to get the expected info that this service's auth dict should contain.

        This public method calls the protected `_required_auth_info` and then validates its
        type to ensure the caller does not get a non-iterable result due to a poor implementation
        by a subclass.

        Returns:
            dict: Required authentication keys, with optional description and
                format they should follow
        """
        req_auth_info = cls._required_auth_info()
        return req_auth_info if isinstance(req_auth_info, dict) else {}

    @classmethod
    @abstractmethod
    def _required_auth_info(cls):
        """Protected method to get the expected info that this service's auth dict should contain.

        This must be implemented by subclasses and provide context as to what authentication
        information is required as well as a description of the data and an optional regex
        that the data should conform to.

        This is called from the public `required_auth_info` method and validated there.

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
        LOGGER.debug('[%s] Sleeping for %d seconds...', self, sleep_for_secs)

        time.sleep(sleep_for_secs)

    def _initialize(self):
        """Method for performing any startup steps, like setting state to running"""
        # Perform another safety check to make sure this is not being invoked already
        if self._config.is_running:
            LOGGER.warning('[%s] App already running', self)
            return False

        # Check if this is an invocation spawned from a previous partial execution
        # Return if the config is marked as 'partial' but the invocation type is wrong
        if not self._config.is_successive_invocation and self._config.is_partial:
            LOGGER.error('[%s] App in partial execution state, exiting', self)
            return False

        LOGGER.info('[%s] Starting app', self)

        LOGGER.info('App executing as a successive invocation: %s',
                    self._config.is_successive_invocation)

        # Validate the auth in the config. This raises an exception upon failure
        self._config.validate_auth(set(self.required_auth_info()))

        self._config.set_starting_timestamp(self.date_formatter())

        self._last_timestamp = self._config.last_timestamp
        self._context = self._config.context

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
            LOGGER.info('Ending last timestamp is the same as the beginning last timestamp. '
                        'This could occur if there were no logs collected for this execution.')

        LOGGER.info('[%s] App complete; gathered %d logs in %d polls.', self,
                    self._gathered_log_count, self._poll_count)

        self._config.last_timestamp = self._last_timestamp
        self._config.context = self._context

        # If there are more logs to poll, invoke this app function again and mark
        # the config as 'partial'. Marking the state as 'partial' prevents
        # scheduled function invocations from running alongside chained invocations.
        if self._more_to_poll:
            self._config.mark_partial()
            self._invoke_successive_app()
            return

        self._config.mark_success()

    def _invoke_successive_app(self):
        """Invoke a successive app function to handle more logs

        This is useful when there were more logs to collect than could be accomplished
        in this execution. Instead of marking the config with 'success' and waiting
        for the next scheduled execution, this will invoke the lambda again with an
        'event' indicating there are more logs to collect. Other scheduled executions
        will not have an 'event' to allow for this type of override, and will exit
        when checking the 'self._config.is_running' property. This allows for chained
        invocations without the worry of duplicated effort or collisions.
        """
        lambda_client = boto3.client('lambda')
        try:
            response = lambda_client.invoke(FunctionName=self._config.function_name,
                                            InvocationType='Event',
                                            Payload=self._config.successive_event,
                                            Qualifier=self._config.function_version)
        except ClientError as err:
            LOGGER.error(
                'An error occurred while invoking a subsequent app function '
                '(\'%s:%s\'). Error is: %s', self._config.function_name,
                self._config.function_version, err.response)
            raise

        LOGGER.info('Invoking successive apps function \'%s\' with Lambda request ID \'%s\'',
                    self._config.function_name, response['ResponseMetadata']['RequestId'])

    def _check_http_response(self, response):
        """Method for checking for a valid HTTP response code

        Returns:
            bool: Indicator of whether or not this request was successful
        """
        success = response is not None and (200 <= response.status_code <= 299)
        if not success:
            LOGGER.error('[%s] HTTP request failed: [%d] %s', self, response.status_code,
                         response.content)
        return success

    @safe_timeout
    def _make_get_request(self, full_url, headers, params=None):
        """Method for returning the json loaded response for this GET request

        Returns:
            tuple (bool, dict): False if the was an error performing the request,
                and the dictionary loaded from the json response
        """
        LOGGER.debug('[%s] Making GET request on poll #%d', self, self._poll_count)

        # Perform the request and return the response as a dict
        response = requests.get(full_url,
                                headers=headers,
                                params=params,
                                timeout=self._DEFAULT_REQUEST_TIMEOUT)

        return self._check_http_response(response), response.json()

    @safe_timeout
    def _make_post_request(self, full_url, headers, data, is_json=True):
        """Method for returning the json loaded response for this POST request

        Returns:
            tuple (bool, dict|None): The first return value will be False if there
                was an error performing the request.
                The second return value will be None if JSONDecodeError raised,
                otherwise it will be the dictionary loaded from the json response.
        """
        LOGGER.debug('[%s] Making POST request on poll #%d', self, self._poll_count)

        # Perform the request and return the response as a dict
        if is_json:
            response = requests.post(full_url,
                                     headers=headers,
                                     json=data,
                                     timeout=self._DEFAULT_REQUEST_TIMEOUT)
        else:
            # if content type is form-encoded, the param is 'data' rather than 'json'
            response = requests.post(full_url,
                                     headers=headers,
                                     data=data,
                                     timeout=self._DEFAULT_REQUEST_TIMEOUT)

        try:
            return self._check_http_response(response), response.json()
        except JSONDecodeError:
            # https://github.com/airbnb/streamalert/issues/998
            # When response returns Gateway Timeout with status_code 504, the response
            # object will return empty string and raises JSONDecoderError a when .json() refers to.
            # See https://github.com/psf/requests/blob/v2.22.0/requests/models.py#L853
            # Instead of raising exception, we can just return False, None
            return False, None

    @_report_time
    def _gather(self):
        """Protected entry point to perform the gather that returns the time the process took

        Returns:
            float: time, in seconds, for which the function ran
        """
        # Make this request sleep if the API throttles requests
        self._sleep()

        # Increment the poll count
        self._poll_count += 1

        logs = self._gather_logs()

        # Make sure there are logs, this can be False if there was an issue polling
        # of if there are no new logs to be polled
        if not logs:
            self._more_to_poll = False
            LOGGER.error('[%s] Gather process was not able to poll any logs '
                         'on poll #%d', self, self._poll_count)
            return

        # Increment the count of logs gathered
        self._gathered_log_count += len(logs)

        # Utilize the batcher to send logs to the classifier function
        self._batcher.send_logs(logs)

        LOGGER.debug('Updating config last timestamp from %s to %s', self._config.last_timestamp,
                     self._last_timestamp)

        # Save the config's last timestamp after each function run
        self._config.last_timestamp = self._last_timestamp

    def gather(self):
        """Public method for actual gathering of logs"""
        # Initialize the app, saving state to 'running'
        if not self._initialize():
            return

        try:
            # Add a 50% buffer to the time it took to account for some unforeseen delay and to give
            # this function enough time to spawn a new invocation if there are more logs to poll
            while (((self._gather() * self._POLL_BUFFER_MULTIPLIER) + self._sleep_seconds()) <
                   self._remaining_seconds):
                LOGGER.debug('[%s] More logs to poll: %s', self, self._more_to_poll)
                self._config.report_remaining_seconds()
                if not self._more_to_poll:
                    break

                # Reset the boolean indicating that there is more data to poll. Subclasses should
                # set this to 'True' within their implementation of the '_gather_logs' function
                self._more_to_poll = not self._more_to_poll

            LOGGER.debug(
                '[%s] Gathered all logs possible for this execution. More logs to poll: '
                '%s', self, self._more_to_poll)

            self._config.report_remaining_seconds()

            # Finalize, saving state to 'succeeded'
            self._finalize()
        finally:
            # Make sure the config is not left marked as running, which could be problematic
            if self._config and self._config.is_running:
                self._config.mark_failure()

    @property
    def _remaining_seconds(self):
        return (self._config.remaining_ms() / 1000.0) - self._EOF_SECONDS_BUFFER

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
import calendar
import json
import re
import time
from datetime import datetime

import backoff
import boto3
from botocore import client
from botocore.exceptions import ClientError

from streamalert.apps.exceptions import (AppAuthError, AppConfigError,
                                         AppStateError)
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)
AWS_RATE_RE = re.compile(r'^rate\(((1) (minute|hour|day)|'
                         r'([2-9]+|[1-9]\d+) (minutes|hours|days))\)$')
AWS_RATE_HELPER = 'http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html'


class AppConfig:
    """Centralized config for handling configuration loading/parsing"""
    MAX_STATE_SAVE_TRIES = 5
    BOTO_TIMEOUT = 5
    SSM_CLIENT = None

    AUTH_CONFIG_SUFFIX = 'auth'
    STATE_CONFIG_SUFFIX = 'state'

    _STATE_KEY = 'current_state'
    _TIME_KEY = 'last_timestamp'
    _CONTEXT_KEY = 'context'
    _STATE_DESCRIPTION = 'State information for the \'{}\' app for use in the \'{}\' function'

    class States:
        """States object to encapsulate various acceptable states"""
        PARTIAL = 'partial'
        RUNNING = 'running'
        SUCCEEDED = 'succeeded'
        FAILED = 'failed'

    class Events:
        """Events object to encapsulate various acceptable events"""
        SUCCESSIVE_INVOKE = 'successive'

    def __init__(self, auth_config, state_config, event, func_name, func_version):
        self._validate_event(event)
        self._auth_config = auth_config
        self._current_state = state_config.get(self._STATE_KEY)
        self._last_timestamp = state_config.get(self._TIME_KEY)
        self._context = state_config.get(self._CONTEXT_KEY, {})
        self._event = event
        self.function_name = func_name
        self.function_version = func_version
        self.start_last_timestamp = None

    def set_starting_timestamp(self, date_format):
        self.start_last_timestamp = self._determine_last_time(date_format)

    @property
    def successive_event(self):
        """Return formatted json for event representing a successive invocation"""
        event = {'invocation_type': self.Events.SUCCESSIVE_INVOKE}
        event |= self._event
        return json.dumps(event)

    @property
    def _app_type(self):
        """The app type for this config"""
        return self._event['app_type']

    @property
    def _schedule(self):
        """The rate schedule on which this app runs"""
        return self._event['schedule_expression']

    @property
    def destination_function(self):
        """The destination function name where logs should be sent"""
        return self._event['destination_function_name']

    @property
    def _invocation_type(self):
        """The invocation type for this function, can be None"""
        return self._event.get('invocation_type')

    @property
    def _state_name(self):
        """The name of the state parameter in ssm"""
        return f'{self.function_name}_{self.STATE_CONFIG_SUFFIX}'

    @staticmethod
    def remaining_ms():
        """Static method that gets mapped to the address of the AWS Lambda
        context object's "get_remaining_time_in_millis" method so we can
        monitor execution. This is helpful to save state when nearing the
        timeout for a lambda execution.
        """

    @classmethod
    def required_event_keys(cls):
        """Get the set of keys that are required in the input event

        Returns:
            set: Set of required keys
        """
        return {'app_type', 'destination_function_name', 'schedule_expression'}

    @classmethod
    def load_config(cls, event, context):
        """Load the configuration for this app invocation

        Args:
            event (dict): The AWS Lambda input event, which is JSON serialized to a dictionary
            context (LambdaContext): The AWS LambdaContext object, passed in via the handler.

        Returns:
            AppConfig: Configuration for the running application
        """
        # Patch out the protected _remaining_ms method to the AWS timing function
        AppConfig.remaining_ms = context.get_remaining_time_in_millis
        func_name = context.function_name
        func_version = context.function_version

        # Get full parameter names for authentication and state parameters
        auth_param_name = '_'.join([func_name, cls.AUTH_CONFIG_SUFFIX])
        state_param_name = '_'.join([func_name, cls.STATE_CONFIG_SUFFIX])

        # Get the loaded parameters and a list of any invalid ones from parameter store
        params, invalid_params = cls._get_parameters(auth_param_name, state_param_name)

        # Check to see if the authentication param is in the invalid params list
        if auth_param_name in invalid_params:
            raise AppConfigError(
                f'Could not load authentication parameter required for this app: {auth_param_name}')

        LOGGER.debug('Retrieved parameters from parameter store: %s',
                     cls._scrub_auth_info(params, auth_param_name))
        LOGGER.debug('Invalid parameters could not be retrieved from parameter store: %s',
                     invalid_params)

        # Load the authentication info. This data can vary from service to service
        auth_config = {
            key: value if isinstance(value, str) else value
            for key, value in params[auth_param_name].items()
        }
        state_config = params.get(state_param_name, {})

        return AppConfig(auth_config, state_config, event, func_name, func_version)

    @staticmethod
    def _scrub_auth_info(param_info, auth_param_name):
        """Scrub sensitive authentication info from a copy of the retrieved parameters.

        By scrubbing/masking the authentication info, it allows us to safely print the info
        to stdout (logger) without revealing secrets needed for authentication.

        Args:
            param_info (dict): All of the parameter information pulled from Parameter Store
            auth_param_name (str): The key for the auth config info within the param_info

        Returns:
            dict: A copy of the passed param_info dictionary with the authentication
                information scrubbed with an asterisk for each character
        """
        info = param_info.copy()
        info[auth_param_name] = {
            key: '*' * len(str(value))
            for key, value in info[auth_param_name].items()
        }

        return info

    def validate_auth(self, required_keys):
        """Validate the authentication dictionary retrieved from AWS Parameter Store

        Args:
            required_keys (set): required authentication keys for the running app

        Returns:
            bool: ndicator of successful validation
        """
        # The config validates that the 'auth' dict was loaded, but do a safety check here
        if not self.auth:
            raise AppAuthError(f'[{self}] Auth config is empty')

        auth_key_diff = required_keys.difference(set(self.auth))
        if not auth_key_diff:
            return True

        missing_auth_keys = ', '.join(f"\'{key}\'" for key in auth_key_diff)
        raise AppAuthError(
            f'[{self}] Auth config is missing the following required keys: {missing_auth_keys}')

    @classmethod
    def _get_parameters(cls, *names):
        """Simple helper function to house the boto3 ssm client get_parameters operations

        Args:
            names (list): A list of parameter names to retrieve from the aws ssm
                parameter store

        Returns:
            tuple (dict, list): Dictionary with the load parameter names as keys
                and the actual parameter (as a dictionary) as the value. The seconary
                list that is returned contains any invalid parameters that were not loaded
        """
        # Create the ssm boto3 client that will be cached and used throughout this execution
        # if one does not exist already
        if AppConfig.SSM_CLIENT is None:
            boto_config = client.Config(connect_timeout=cls.BOTO_TIMEOUT,
                                        read_timeout=cls.BOTO_TIMEOUT)
            AppConfig.SSM_CLIENT = boto3.client('ssm', config=boto_config)

        LOGGER.debug('Retrieving values from parameter store with names: %s',
                     ', '.join(f"\'{name}\'" for name in names))

        try:
            parameters = AppConfig.SSM_CLIENT.get_parameters(Names=list(names), WithDecryption=True)
        except ClientError as err:
            joined_names = ', '.join(f"\'{name}\'" for name in names)
            raise AppConfigError(f"Could not get parameter with names {joined_names}. Error: {err.response['Error']['Message']}") from err


        decoded_params = {}
        for param in parameters['Parameters']:
            try:
                decoded_params[param['Name']] = json.loads(param['Value'])
            except ValueError as e:
                raise AppConfigError(
                    f"Could not load value for parameter with name \'{param['Name']}\'. The value is not valid json: \'{param['Value']}\'"
                ) from e


        return decoded_params, parameters['InvalidParameters']

    def _determine_last_time(self, date_format):
        """Determine the last time this function was executed and fallback on
        evaluating the rate value if there is no last timestamp available

        Returns:
            int: The unix timestamp for the starting point to fetch logs back to
        """
        if not self.last_timestamp:
            interval_time = self._evaluate_interval()
            current_time = int(calendar.timegm(time.gmtime()))
            time_delta = current_time - interval_time
            LOGGER.debug('Current timestamp: %s seconds. Calculated delta: %s seconds',
                         current_time, time_delta)

            # Request the date format from the app since some services expect different types
            # Using init=False will return the class without instantiating it
            if date_format:
                self.last_timestamp = datetime.utcfromtimestamp(time_delta).strftime(date_format)
            else:
                self.last_timestamp = time_delta

        LOGGER.info('Starting last timestamp set to: %s', self.last_timestamp)

        return self.last_timestamp

    def _save_state(self):
        """Save the current state in the aws ssm paramater store

        Raises:
            AppStateError: If the parameter is not able to be saved
        """
        try:
            param_value = json.dumps({
                self._TIME_KEY: self.last_timestamp,
                self._STATE_KEY: self.current_state,
                self._CONTEXT_KEY: self.context,
            })
        except TypeError as err:
            raise AppStateError('Could not serialize state for name \'{}\'. Error: '
                                '{}'.format(self._state_name, str(err))) from err

        @backoff.on_exception(backoff.expo,
                              ClientError,
                              max_tries=self.MAX_STATE_SAVE_TRIES,
                              jitter=backoff.full_jitter)
        def save():
            """Function to save the value of the state dictionary to parameter store"""
            self.SSM_CLIENT.put_parameter(Name=self._state_name,
                                          Description=self._STATE_DESCRIPTION.format(
                                              self._app_type, self.function_name),
                                          Value=param_value,
                                          Type='SecureString',
                                          Overwrite=True)

        try:
            save()
        except ClientError as err:
            raise AppStateError('Could not save current state to parameter '
                                'store with name \'{}\'. Response: '
                                '{}'.format(self._state_name, err.response)) from err

    @classmethod
    def _validate_event(cls, event):
        """Validate the top level of the config to make sure it has all the right keys

        Raises:
            AppConfigError: If the config is invalid, this exception is raised
        """
        event_key_diff = cls.required_event_keys().difference(set(event))
        if not event_key_diff:
            return

        missing_event_keys = ', '.join(f"\'{key}\'" for key in event_key_diff)
        raise AppConfigError(
            f'App event is missing the following required keys: {missing_event_keys}')

    def _evaluate_interval(self):
        """Get the interval at which this function is executing. This translates
        an AWS Rate Schedule Expression ('rate(2 hours)') into a second interval
        """
        rate_match = AWS_RATE_RE.match(self._schedule)

        if not rate_match:
            raise AppConfigError(f"Invalid \'rate\' interval value: {self._schedule}")

        value = rate_match.group(2) or rate_match.group(4)
        unit = rate_match.group(3) or rate_match.group(5).replace('s', '')

        translate_to_seconds = {'minute': 60, 'hour': 60 * 60, 'day': 60 * 60 * 24}

        interval = int(value) * translate_to_seconds[unit]

        LOGGER.debug('Evaluated rate interval: %d seconds', interval)

        # Get the total seconds that this rate evaluates to
        return interval

    def report_remaining_seconds(self):
        """Log the remaining seconds"""
        LOGGER.info('Lambda remaining seconds: %.2f', self.remaining_ms() / 1000.0)

    @property
    def auth(self):
        """Get the auth dictionary"""
        return self._auth_config

    @property
    def current_state(self):
        """Get the current state of the execution"""
        LOGGER.debug('Getting current_state: %s', self._current_state)
        return self._current_state

    @current_state.setter
    def current_state(self, state):
        """Set the current state of the execution"""
        if not getattr(self.States, str(state).upper(), None):
            LOGGER.error('Current state cannot be saved with value \'%s\'', state)
            return

        if self._current_state == state:
            LOGGER.debug('State is unchanged and will not be saved: %s', state)
            return

        LOGGER.debug('Setting current state to: %s', state)

        self._current_state = state
        self._save_state()

    @property
    def last_timestamp(self):
        """Get the last timestamp"""
        LOGGER.debug('Getting last_timestamp as: %s', self._last_timestamp)
        return self._last_timestamp

    @last_timestamp.setter
    def last_timestamp(self, timestamp):
        """Set the last timestamp"""
        if self._last_timestamp == timestamp:
            LOGGER.debug('Timestamp is unchanged and will not be saved: %s', timestamp)
            return

        LOGGER.debug('Setting last timestamp to: %s', timestamp)

        self._last_timestamp = timestamp
        self._save_state()

    @property
    def context(self):
        """Get an additional context dictionary specific to each app"""
        LOGGER.debug('Getting context: %s', self._context)
        return self._context

    @context.setter
    def context(self, context):
        """Set an additional context dictionary specific to each app"""
        if self._context == context:
            LOGGER.debug('App context is unchanged and will not be saved: %s', context)
            return

        if not isinstance(context, dict):
            raise AppStateError(f'Unable to set context, must be a dict: {context}')

        LOGGER.debug('Setting context to: %s', context)

        self._context = context
        self._save_state()

    @property
    def is_successive_invocation(self):
        """Check if this invocation is a successive invoke from a previous execution"""
        is_successive = self._invocation_type == self.Events.SUCCESSIVE_INVOKE

        LOGGER.debug('Is successive invocation: %s', is_successive)
        return is_successive

    @property
    def is_failing(self):
        """Check if the current state is 'failed'"""
        return self.current_state == self.States.FAILED

    @property
    def is_partial(self):
        """Check if the current state is 'partial'"""
        return self.current_state == self.States.PARTIAL

    @property
    def is_running(self):
        """Check if the current state is 'running'"""
        return self.current_state == self.States.RUNNING

    @property
    def is_success(self):
        """Check if the current state is 'succeeded'"""
        return self.current_state == self.States.SUCCEEDED

    def mark_partial(self):
        """Helper method to mark the state as 'partial'"""
        LOGGER.debug('Marking current_state as: %s', self.States.PARTIAL)
        self.current_state = self.States.PARTIAL

    def mark_running(self):
        """Helper method to mark the state as 'running'"""
        LOGGER.debug('Marking current_state as: %s', self.States.RUNNING)
        self.current_state = self.States.RUNNING

    def mark_success(self):
        """Helper method to mark the state as 'succeeded'"""
        LOGGER.debug('Marking current_state as: %s', self.States.SUCCEEDED)
        self.current_state = self.States.SUCCEEDED

    def mark_failure(self):
        """Helper method to mark the state as 'failed'"""
        LOGGER.debug('Marking current_state as: %s', self.States.FAILED)
        self.current_state = self.States.FAILED

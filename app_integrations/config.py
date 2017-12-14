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
import calendar
from datetime import datetime
import json
import re
import time

import boto3
from botocore.exceptions import ClientError

from app_integrations import LOGGER
from app_integrations.apps.app_base import StreamAlertApp
from app_integrations.exceptions import AppIntegrationConfigError, AppIntegrationStateError

AWS_RATE_RE = re.compile(r'^rate\(((1) (minute|hour|day)|'
                         r'([2-9]+|[1-9]\d+) (minutes|hours|days))\)$')
AWS_RATE_HELPER = 'http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html'

class AppConfig(dict):
    """Centralized config for handling configuration loading/parsing"""
    SSM_CLIENT = None

    BASE_CONFIG_SUFFIX = 'config'
    AUTH_CONFIG_SUFFIX = 'auth'
    STATE_CONFIG_SUFFIX = 'state'

    _STATE_KEY = 'current_state'
    _TIME_KEY = 'last_timestamp'
    _STATE_DESCRIPTION = 'State information for the \'{}\' service for use in the \'{}\' app'

    class States(object):
        """States object to encapsulate various acceptable states"""
        PARTIAL = 'partial'
        RUNNING = 'running'
        SUCCEEDED = 'succeeded'
        FAILED = 'failed'

    class Events(object):
        """Events object to encapsulate various acceptable events"""
        SUCCESSIVE_INVOKE = 'successive_invoke'

    def __init__(self, config, event=None, **kwargs):
        dict.__init__(self, config, **kwargs)
        self._validate_config()
        self._event = event or {}
        self.start_last_timestamp = self._determine_last_time()

    def __setitem__(self, key, value):
        # Do some safety checking so we don't save a malformed state
        if key == self._STATE_KEY and not getattr(self.States, str(value).upper(), None):
            LOGGER.error('Current state cannot be saved with value \'%s\'', value)
            return

        # Cache the old value to see if the new value differs
        current_value = self.get(key)

        dict.__setitem__(self, key, value)

        # If this is a key related to the state config, save the state in parameter store
        if key in self._state_keys() and current_value != value:
            self._save_state()

    @staticmethod
    def remaining_ms():
        """Static method that gets mapped to the address of the AWS Lambda
        context object's "get_remaining_time_in_millis" method so we can
        monitor execution. This is helpful to save state when nearing the
        timeout for a lambda execution.
        """

    @classmethod
    def required_base_config_keys(cls):
        """Get the base set of keys that are required in the config

        Returns:
            set: Set of required base keys
        """
        return {'type', 'app_name', 'prefix', 'cluster', 'interval'}

    @classmethod
    def _state_keys(cls):
        return {cls._STATE_KEY, cls._TIME_KEY}

    @classmethod
    def load_config(cls, context, event):
        """Load the configuration for this app invocation

        Args:
            context (LambdaContext): The AWS LambdaContext object, passed in via the handler.

        Returns:
            AppConfig: Subclassed dictionary with the below structure that contains all of the
                 methods for configuration validation, updating, saving, etc:
                    {
                        'type': <type>,
                        'cluster': <cluster>,
                        'prefix': <prefix>,
                        'app_name': <app_name>,
                        'interval': <rate_interval>,
                        'region': <aws_region>,
                        'account_id': <aws_account_id>,
                        'function_name': <function_name>,
                        'qualifier': <qualifier>,
                        'last_timestamp': <time>,
                        'current_state': <running|succeeded|failed>,
                        'auth': {
                            'req_auth_item_01': <req_auth_value_01>
                        }
                    }
        """
        # Load the base config from the context that will get updated with other info
        base_config = AppConfig._parse_context(context)

        LOGGER.debug('Loaded env config: %s', base_config)

        # Create the ssm boto3 client that will be cached and used throughout this execution
        # if one does not exist already
        if AppConfig.SSM_CLIENT is None:
            AppConfig.SSM_CLIENT = boto3.client('ssm', region_name=base_config['region'])

        # Generate a map of all the suffixes and full parameter names
        param_names = {key: '_'.join([base_config['function_name'], key])
                       for key in {cls.AUTH_CONFIG_SUFFIX,
                                   cls.BASE_CONFIG_SUFFIX,
                                   cls.STATE_CONFIG_SUFFIX}}

        LOGGER.debug('Parameter suffixes and names: %s', param_names)

        # Get the loaded parameters and a list of any invalid ones from parameter store
        params, invalid_params = AppConfig._get_parameters(param_names.values())
        LOGGER.debug('Retrieved parameters from parameter store: %s',
                     cls._scrub_auth_info(params, param_names[cls.AUTH_CONFIG_SUFFIX]))
        LOGGER.debug('Invalid parameters could not be retrieved from parameter store: %s',
                     invalid_params)

        # Check to see if there are any required parameters in the invalid params list
        missing_required_params = [param
                                   for param in invalid_params
                                   if param != param_names[cls.STATE_CONFIG_SUFFIX]]

        if missing_required_params:
            joined_params = ', '.join('\'{}\''.format(param) for param in missing_required_params)
            raise AppIntegrationConfigError('Could not load parameters required for this '
                                            'configuration: {}'.format(joined_params))

        # Update the env config with the base config values
        base_config.update(params[param_names[cls.BASE_CONFIG_SUFFIX]])

        # The state config can be None with first time deploys, so us a lookup and
        # add default empty values if there is no state found
        base_config.update(params.get(param_names[cls.STATE_CONFIG_SUFFIX],
                                      {cls._STATE_KEY: None, cls._TIME_KEY: None}))

        # Add the auth config info to the 'auth' key since these key/values can vary
        # from service to service
        base_config[cls.AUTH_CONFIG_SUFFIX] = {
            key: value.encode('utf-8') if isinstance(value, unicode) else value
            for key, value in params[param_names[cls.AUTH_CONFIG_SUFFIX]].iteritems()
        }

        return AppConfig(base_config, event)

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
        if not auth_param_name in param_info:
            return param_info

        info = param_info.copy()
        info[auth_param_name] = {key: '*' * len(str(value))
                                 for key, value in info[auth_param_name].iteritems()}

        return info

    @staticmethod
    def _get_parameters(names):
        """Simple helper function to house the boto3 ssm client get_parameters operations

        Args:
            names (list): A list of parameter names to retrieve from the aws ssm
                parameter store

        Returns:
            tuple (dict, list): Dictionary with the load parameter names as keys
                and the actual parameter (as a dictionary) as the value. The seconary
                list that is returned contains any invalid parameters that were not loaded
        """
        LOGGER.debug('Retrieving values from parameter store with names: %s',
                     ', '.join('\'{}\''.format(name) for name in names))
        try:
            parameters = AppConfig.SSM_CLIENT.get_parameters(
                Names=names,
                WithDecryption=True
            )
        except ClientError as err:
            joined_names = ', '.join('\'{}\''.format(name) for name in names)
            raise AppIntegrationConfigError('Could not get parameter with names {}. Error: '
                                            '{}'.format(joined_names,
                                                        err.response['Error']['Message']))

        decoded_params = {}
        for param in parameters['Parameters']:
            try:
                decoded_params[param['Name']] = json.loads(param['Value'])
            except ValueError:
                raise AppIntegrationConfigError('Could not load value for parameter with '
                                                'name \'{}\'. The value is not valid json: '
                                                '\'{}\''.format(param['Name'], param['Value']))

        return decoded_params, parameters['InvalidParameters']

    @staticmethod
    def _parse_context(context):
        """Parse the LambdaContext from the running Lambda function. This also sets
        the address of the class's remaining_ms method to address of the LambdaContext's
        get_remaining_time_in_millis method for ease of use. The invoked_function_arn
        is used to extract fields for use throughout execution.

        invoked_function_arn Example:
            arn:aws:lambda:us-east-1:123456789012:function:function_name:function_alias

        Args:
            context (LambdaContext): The AWS LambdaContext object, passed in via the handler.

        Sets:
            AppConfig.remaining_ms

        Returns:
            dict: Loaded base config constructed from the parts of the function arn
        """
        # Patch out the protected _remaining_ms method to the AWS function
        AppConfig.remaining_ms = context.get_remaining_time_in_millis

        arn = context.invoked_function_arn.split(':')

        return {
            'region': arn[3],
            'account_id': arn[4],
            'function_name': arn[6],
            'qualifier': arn[7]
        }

    def _determine_last_time(self):
        """Determine the last time this function was executed and fallback on
        evaluating the rate value if there is no last timestamp available

        Returns:
            int: The unix timestamp for the starting point to fetch logs back to
        """
        if not self.last_timestamp:
            interval_time = self.evaluate_interval()
            current_time = int(calendar.timegm(time.gmtime()))
            time_delta = current_time - interval_time
            LOGGER.debug('Current timestamp: %s seconds. Calculated delta: %s seconds',
                         current_time, time_delta)

            # Request the date format from the app since some services expect different types
            # Using init=False will return the class without instantiating it
            date_format = StreamAlertApp.get_app(self, init=False).date_formatter()
            if date_format:
                self.last_timestamp = datetime.utcfromtimestamp(time_delta).strftime(date_format)
            else:
                self.last_timestamp = time_delta

        LOGGER.info('Starting last timestamp set to: %s', self.last_timestamp)

        return self.last_timestamp

    def _save_state(self):
        """Function to save the value of this dictionary to parameter store

        Raises:
            AppIntegrationStateError: If state parameter cannot be saved, this is raised
        """
        state_name = '_'.join([self['function_name'], self.STATE_CONFIG_SUFFIX])
        param_value = json.dumps({key: self[key] for key in self._state_keys()})
        try:
            AppConfig.SSM_CLIENT.put_parameter(
                Name=state_name,
                Description=self._STATE_DESCRIPTION.format(self['type'], self['app_name']),
                Value=param_value,
                Type='SecureString',
                Overwrite=True
            )
        except ClientError as err:
            raise AppIntegrationStateError('Could not save current state to parameter '
                                           'store with name \'{}\'. Response: '
                                           '{}'.format(state_name, err.response))

    def _validate_config(self):
        """Validate the top level of the config to make sure it has all the right keys

        Raises:
            AppIntegrationConfigError: If the config is invalid, this exception is raised
        """
        if not self:
            raise AppIntegrationConfigError('App config is empty')

        required_keys = self.required_base_config_keys()
        required_keys.update({'region', 'account_id', 'function_name', 'qualifier', 'auth'})

        config_key_diff = required_keys.difference(set(self))
        if not config_key_diff:
            return

        missing_config_keys = ', '.join('\'{}\''.format(key) for key in config_key_diff)
        raise AppIntegrationConfigError('App config is missing the following required '
                                        'keys: {}'.format(missing_config_keys))

    def evaluate_interval(self):
        """Get the interval at which this function is executing. This translates
        an AWS Rate Schedule Expression ('rate(2 hours)') into a second interval
        """
        if 'interval' not in self:
            raise AppIntegrationConfigError('The \'interval\' value is not defined in the config')

        rate_match = AWS_RATE_RE.match(self['interval'])

        if not rate_match:
            raise AppIntegrationConfigError('Invalid \'rate\' interval value: '
                                            '{}'.format(self['interval']))

        value = rate_match.group(2) or rate_match.group(4)
        unit = rate_match.group(3) or rate_match.group(5).replace('s', '')

        translate_to_seconds = {'minute': 60,
                                'hour': 60*60,
                                'day': 60*60*24}

        interval = int(value) * translate_to_seconds[unit]

        LOGGER.debug('Evaluated rate interval: %d seconds', interval)

        # Get the total seconds that this rate evaluates to
        return interval

    def report_remaining_seconds(self):
        """Log the remaining seconds"""
        LOGGER.info('Lambda remaining seconds: %.2f', self.remaining_ms() / 1000.0)

    @property
    def auth(self):
        """Get the auth sub dictionary from the config"""
        return self.get(self.AUTH_CONFIG_SUFFIX)

    @property
    def current_state(self):
        """Cache the current time to be written to the config"""
        LOGGER.debug('Getting current_state: %s', self.get(self._STATE_KEY))
        return self.get(self._STATE_KEY)

    @property
    def last_timestamp(self):
        """Get the last time from the config"""
        LOGGER.debug('Getting last_timestamp as: %s', self.get(self._TIME_KEY))
        return self.get(self._TIME_KEY)

    @last_timestamp.setter
    def last_timestamp(self, timestamp):
        """Set the last time in the config"""
        LOGGER.debug('Setting last_timestamp as: %s', timestamp)
        self[self._TIME_KEY] = timestamp

    @property
    def is_successive_invocation(self):
        """Check if this invocation is a successive invoke from a previous execution"""
        is_successive = self._event.get('invocation_type') == self.Events.SUCCESSIVE_INVOKE

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
        self[self._STATE_KEY] = self.States.PARTIAL

    def mark_running(self):
        """Helper method to mark the state as 'running'"""
        LOGGER.debug('Marking current_state as: %s', self.States.RUNNING)
        self[self._STATE_KEY] = self.States.RUNNING

    def mark_success(self):
        """Helper method to mark the state as 'succeeded'"""
        LOGGER.debug('Marking current_state as: %s', self.States.SUCCEEDED)
        self[self._STATE_KEY] = self.States.SUCCEEDED

    def mark_failure(self):
        """Helper method to mark the state as 'failed'"""
        LOGGER.debug('Marking current_state as: %s', self.States.FAILED)
        self[self._STATE_KEY] = self.States.FAILED

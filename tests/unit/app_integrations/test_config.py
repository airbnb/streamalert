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
# pylint: disable=no-self-use,protected-access,attribute-defined-outside-init
from mock import patch
from nose.tools import assert_equal, assert_false, assert_items_equal, assert_true, raises

from app_integrations.config import AppConfig
from app_integrations.exceptions import AppIntegrationConfigError, AppIntegrationStateError
from tests.unit.app_integrations import FUNCTION_NAME
from tests.unit.app_integrations.test_helpers import (
    get_mock_context,
    MockSSMClient
)


class TestAppIntegrationConfig(object):
    """Test class for AppIntegrationConfig"""

    def setup(self):
        """Setup before each method"""
        self.ssm_patcher = patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient())
        self.mock_ssm = self.ssm_patcher.start()
        self._config = AppConfig.load_config(get_mock_context(),
                                             {'invocation_type': 'successive_invoke'})

    def teardown(self):
        """Teardown after each method"""
        self.ssm_patcher.stop()

    def test_parse_context(self):
        """AppIntegrationConfig - Parse Context"""
        mock_context = get_mock_context()
        result = AppConfig._parse_context(mock_context)

        assert_equal(AppConfig.remaining_ms, mock_context.get_remaining_time_in_millis)
        assert_equal(AppConfig.remaining_ms(), 100)
        assert_equal(result['function_name'], FUNCTION_NAME)

    def test_load_config(self):
        """AppIntegrationConfig - Load config from SSM"""
        assert_equal(len(self._config.keys()), 12)

    @patch('boto3.client')
    def test_load_config_new_client(self, boto_mock):
        """AppIntegrationConfig - Load config, new SSM client"""
        boto_mock.return_value = MockSSMClient(app_type='onelogin_events')
        with patch.object(AppConfig, 'SSM_CLIENT', None):
            self._config = AppConfig.load_config(get_mock_context(), None)
            boto_mock.assert_called_with('ssm', region_name='us-east-1')

    @raises(AppIntegrationConfigError)
    def test_load_config_bad(self):
        """AppIntegrationConfig - Load config from SSM, missing key"""
        # Remove one of the required keys from the state
        del self._config['qualifier']
        self._config._validate_config()

    @raises(AppIntegrationConfigError)
    def test_load_config_empty(self):
        """AppIntegrationConfig - Load config from SSM, empty config"""
        # Empty the config so the dict validates to False
        self._config.clear()
        self._config._validate_config()

    def test_get_param(self):
        """AppIntegrationConfig - Get parameter"""
        param, _ = AppConfig._get_parameters(['{}_config'.format(FUNCTION_NAME)])

        assert_items_equal(param['{}_config'.format(FUNCTION_NAME)].keys(),
                           {'cluster', 'app_name', 'type', 'prefix', 'interval'})

    @raises(AppIntegrationConfigError)
    def test_get_param_bad_value(self):
        """AppIntegrationConfig - Get parameter, bad json value"""
        config_name = '{}_config'.format(FUNCTION_NAME)
        with patch.dict(AppConfig.SSM_CLIENT._parameters, {config_name: 'bad json'}):
            AppConfig._get_parameters([config_name])

    @raises(AppIntegrationConfigError)
    def test_get_param_client_error(self):
        """AppIntegrationConfig - Get parameter, Exception"""
        self.mock_ssm.raise_exception = True
        AppConfig._get_parameters([])

    @raises(AppIntegrationConfigError)
    def test_evaluate_interval_no_interval(self):
        """AppIntegrationConfig - Evaluate Interval, No Interval"""
        del self._config['interval']
        self._config.evaluate_interval()

    @raises(AppIntegrationConfigError)
    def test_evaluate_interval_invalid(self):
        """AppIntegrationConfig - Evaluate Interval, Invalid Interval"""
        self._config['interval'] = 'rate(1 hours)'
        self._config.evaluate_interval()

    def test_evaluate_interval(self):
        """AppIntegrationConfig - Evaluate Interval"""
        self._config['interval'] = 'rate(5 hours)'
        assert_equal(self._config.evaluate_interval(), 3600 * 5)

    @patch('calendar.timegm')
    def test_determine_last_timestamp_duo(self, time_mock):
        """AppIntegrationConfig - Determine Last Timestamp, Duo"""
        # Reset the last timestamp to None
        self._config.last_timestamp = None

        # Use a mocked current time
        current_time = 1234567890
        time_mock.return_value = current_time
        self._config['interval'] = 'rate(5 hours)'
        assert_equal(self._config._determine_last_time(), 1234567890 - (3600 * 5))

    @patch('calendar.timegm')
    def test_determine_last_timestamp_onelogin(self, time_mock):
        """AppIntegrationConfig - Determine Last Timestamp, OneLogin"""
        with patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient(app_type='onelogin_events')):
            self._config = AppConfig.load_config(get_mock_context(), None)

            # Reset the last timestamp to None
            self._config.last_timestamp = None

            # Use a mocked current time
            time_mock.return_value = 1234567890
            assert_equal(self._config._determine_last_time(), '2009-02-13T22:31:30Z')

    @patch('calendar.timegm')
    def test_determine_last_timestamp_gsuite(self, time_mock):
        """AppIntegrationConfig - Determine Last Timestamp, GSuite"""
        with patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient(app_type='gsuite_admin')):
            self._config = AppConfig.load_config(get_mock_context(), None)

            # Reset the last timestamp to None
            self._config.last_timestamp = None

            # Use a mocked current time
            time_mock.return_value = 1234567890
            assert_equal(self._config._determine_last_time(), '2009-02-13T22:31:30Z')

    @patch('calendar.timegm')
    def test_determine_last_timestamp_box(self, time_mock):
        """AppIntegrationConfig - Determine Last Timestamp, Box"""
        with patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient(app_type='box_admin_events')):
            self._config = AppConfig.load_config(get_mock_context(), None)

            # Reset the last timestamp to None
            self._config.last_timestamp = None

            # Use a mocked current time
            time_mock.return_value = 1234567890
            assert_equal(self._config._determine_last_time(), '2009-02-13T22:31:30-00:00')

    @patch('logging.Logger.error')
    def test_set_item(self, log_mock):
        """AppIntegrationConfig - Set Item, Bad Value"""
        bad_state = 'bad value'
        self._config['current_state'] = bad_state
        log_mock.assert_called_with('Current state cannot be saved with value \'%s\'', bad_state)

    def test_is_successive_invocation(self):
        """AppIntegrationConfig - Is Successive Invocation"""
        assert_true(self._config.is_successive_invocation)
        self._config = AppConfig.load_config(get_mock_context(), None)
        assert_false(self._config.is_successive_invocation)

    @raises(AppIntegrationStateError)
    def test_save_state_exception(self):
        """AppIntegrationConfig - Save State, Exception"""
        self.mock_ssm.raise_exception = True
        self._config['current_state'] = 'RUNNING'

    def test_mark_failure(self):
        """AppIntegrationConfig - Mark Failure"""
        self._config.mark_failure()
        assert_equal(self._config['current_state'], 'failed')

    def test_is_failing(self):
        """AppIntegrationConfig - Check If Failing"""
        assert_false(self._config.is_failing)

    def test_is_success(self):
        """AppIntegrationConfig - Check If Success"""
        assert_false(self._config.is_success)

    @patch('app_integrations.config.AppConfig._save_state')
    def test_suppress_state_save_no_change(self, save_mock):
        """AppIntegrationConfig - Suppress Save State on No Change"""
        # Try to mark with success more than once
        self._config.mark_success()
        self._config.mark_success()

        save_mock.assert_called_once()

    @patch('app_integrations.config.AppConfig._save_state')
    def test_suppress_state_save(self, save_mock):
        """AppIntegrationConfig - Save State on Change"""
        # Try to mark with failure followed by success
        self._config.mark_failure()
        self._config.mark_success()

        assert_equal(save_mock.call_count, 2)

    def test_scrub_auth_info(self):
        """AppIntegrationConfig - Scrub Auth Info"""
        auth_key = '{}_auth'.format(FUNCTION_NAME)
        param_dict = {auth_key: self._config.auth}
        scrubbed_config = self._config._scrub_auth_info(param_dict, auth_key)
        assert_equal(scrubbed_config[auth_key]['api_hostname'],
                     '*' * len(self._config.auth['api_hostname']))
        assert_equal(scrubbed_config[auth_key]['integration_key'],
                     '*' * len(self._config.auth['integration_key']))
        assert_equal(scrubbed_config[auth_key]['secret_key'],
                     '*' * len(self._config.auth['secret_key']))

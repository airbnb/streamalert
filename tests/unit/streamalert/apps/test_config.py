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
import json
import os
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_ssm

from streamalert.apps.config import AppConfig
from streamalert.apps.exceptions import (AppAuthError, AppConfigError,
                                         AppStateError)
from tests.unit.streamalert.apps.test_helpers import get_event, put_mock_params
from tests.unit.streamalert.shared.test_config import get_mock_lambda_context


@mock_ssm
@patch.object(AppConfig, 'MAX_STATE_SAVE_TRIES', 1)
class TestAppConfig:
    """Test class for AppConfig"""
    # pylint: disable=protected-access,no-self-use,too-many-public-methods

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup before each method"""
        # pylint: disable=attribute-defined-outside-init
        self._test_app_name = 'test_app'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._config = AppConfig.load_config(self._event, self._context)

    @pytest.mark.xfail(raises=AppConfigError)
    def test_load_config_bad_event(self):
        """AppConfig - Load config with a bad event"""
        # Remove one of the required keys from the state
        event = get_event(self._test_app_name)
        del event['destination_function_name']
        AppConfig.load_config(event, get_mock_lambda_context(self._test_app_name))

    @pytest.mark.xfail(raises=AppConfigError)
    def test_evaluate_interval_invalid(self):
        """AppConfig - Evaluate Interval, Invalid Interval"""
        self._config._event['schedule_expression'] = 'rate(1 hours)'
        self._config._evaluate_interval()

    def test_validate_auth_(self):
        """AppConfig - Validate Authentication Info"""
        assert self._config.validate_auth({'host', 'secret'})

    @pytest.mark.xfail(raises=AppAuthError)
    def test_validate_auth_empty(self):
        """AppConfig - Validate Authentication Info, No Auth"""
        self._config._auth_config.clear()
        self._config.validate_auth({'host', 'secret'})

    @pytest.mark.xfail(raises=AppAuthError)
    def test_validate_auth_missing_key(self):
        """AppConfig - Validate Authentication Info, Missing Auth Key"""
        self._config.validate_auth({'new_key'})

    def test_successive_event(self):
        """AppConfig - Get Successive Event"""
        event = json.loads(self._config.successive_event)
        expected_event = {
            'app_type': 'test_app',
            'schedule_expression': 'rate(10 minutes)',
            'destination_function_name':
                'unit_test_prefix_unit_test_cluster_streamalert_classifier',
            'invocation_type': 'successive'
        }
        assert event == expected_event

    def test_set_starting_timestamp(self):
        """AppConfig - Set Starting Timestamp"""
        assigned_value = 'test'
        self._config.last_timestamp = assigned_value
        self._config.set_starting_timestamp(None)
        assert self._config.start_last_timestamp == assigned_value

    @patch('calendar.timegm')
    def test_determine_last_time_no_format(self, time_mock):
        """AppConfig - Determine Last Timestamp, No Format"""
        self._config.last_timestamp = None
        time_mock.return_value = 1000
        expected_result = 400
        result = self._config._determine_last_time(None)
        assert result == expected_result

    @patch('calendar.timegm')
    def test_determine_last_time_formatted(self, time_mock):
        """AppConfig - Determine Last Timestamp, Value Set"""
        self._config.last_timestamp = None
        time_mock.return_value = 1000
        expected_result = '1970-01-01T00:06:40-00:00'
        result = self._config._determine_last_time('%Y-%m-%dT%H:%M:%S-00:00')
        assert result == expected_result

    @pytest.mark.xfail(raises=AppConfigError)
    def test_get_parameters_invalid_json(self):
        """AppConfig - Get Parameters, Invalid JSON"""
        with patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'}):
            key = f'{self._test_app_name}_state'
            boto3.client('ssm').put_parameter(
                Name=key,
                Value='foobar',
                Type='SecureString',
                Overwrite=True
            )
            self._config._get_parameters(key)

    @pytest.mark.xfail(raises=AppConfigError)
    @patch('streamalert.apps.config.AppConfig.SSM_CLIENT')
    def test_get_parameters_exception(self, client_mock):
        """AppConfig - Get Parameters, ClientError"""
        with patch.object(AppConfig, 'MAX_STATE_SAVE_TRIES', 1):
            client_mock.get_parameters.side_effect = ClientError(
                {'Error': {'Code': 'TEST', 'Message': 'BadError'}}, 'GetParameters')
            self._config._get_parameters(f'{self._test_app_name}_state')

    @patch('streamalert.apps.config.json')
    def test_get_parameters_bad_names(self, json_mock):
        """AppConfig - Get parameter, Bad Names"""
        _, invalid_names = AppConfig._get_parameters('bad_name')
        assert invalid_names[0] == 'bad_name'
        json_mock.loads.assert_not_called()

    def test_evaluate_interval(self):
        """AppConfig - Evaluate Interval"""
        assert self._config._evaluate_interval() == 60 * 10

    @pytest.mark.xfail(raises=AppStateError)
    @patch('streamalert.apps.config.AppConfig.SSM_CLIENT')
    def test_save_state_error(self, client_mock):
        """AppConfig - Save State, Error"""
        with patch.object(AppConfig, 'MAX_STATE_SAVE_TRIES', 1):
            client_mock.put_parameter.side_effect = ClientError(
                {'Error': {'Code': 'TEST'}}, 'PutParameter')
            self._config._save_state()

    @patch('logging.Logger.error')
    def test_set_item(self, log_mock):
        """AppConfig - Set Item, Bad Value"""
        bad_state = 'bad value'
        self._config.current_state = bad_state
        log_mock.assert_called_with('Current state cannot be saved with value \'%s\'', bad_state)

    @patch('streamalert.apps.config.AppConfig._save_state')
    def test_suppress_state_save_no_change(self, save_mock):
        """AppConfig - Suppress Save State on No Change"""
        # Try to mark with success more than once
        self._config.mark_running()
        self._config.mark_running()

        save_mock.assert_called_once()

    @patch('streamalert.apps.config.AppConfig._save_state')
    def test_suppress_state_save(self, save_mock):
        """AppConfig - Save State on Change"""
        # Try to mark with failure followed by success
        self._config.mark_failure()
        self._config.mark_success()

        assert save_mock.call_count == 2

    def test_scrub_auth_info(self):
        """AppConfig - Scrub Auth Info"""
        auth_key = 'test_auth'
        param_dict = {auth_key: {'api_hostname': 'test_data'}}
        scrubbed_config = self._config._scrub_auth_info(param_dict, auth_key)
        assert scrubbed_config[auth_key]['api_hostname'] == '*********'

    @patch('logging.Logger.info')
    def test_report_remaining_seconds(self, log_mock):
        """AppConfig - Report Remaining Seconds"""
        self._config.report_remaining_seconds()
        log_mock.assert_called_with('Lambda remaining seconds: %.2f', 0.1)

    @patch('streamalert.apps.config.AppConfig._save_state')
    def test_set_last_timestamp_same(self, save_mock):
        """AppConfig - Set Last Timestamp, Same Value"""
        self._config.last_timestamp = 1234567890
        save_mock.assert_not_called()

    @patch('streamalert.apps.config.AppConfig._save_state')
    def test_set_context_new(self, save_mock):
        """AppConfig - Set Context, New Value"""
        self._config.context = {"key": "value"}
        save_mock.assert_called_once()

    @patch('streamalert.apps.config.AppConfig._save_state')
    def test_set_context_same(self, save_mock):
        """AppConfig - Set Context, Same Value"""
        self._config.context = {}
        save_mock.assert_not_called()

    @pytest.mark.xfail(raises=AppStateError)
    def test_set_context_not_a_dictionary(self):
        """AppConfig - Context not a Dictionary"""
        self._config.context = [1, 2, 3]

    @pytest.mark.xfail(raises=AppStateError)
    def test_set_context_not_serializable(self):
        """AppConfig - Context not Serializable"""
        self._config.context = {"key": object()}

    def test_is_failing(self):
        """AppConfig - Check If Failing"""
        assert not self._config.is_failing

    def test_is_partial(self):
        """AppConfig - Check If Partial Run"""
        assert not self._config.is_partial

    def test_is_running(self):
        """AppConfig - Check If Running"""
        assert not self._config.is_running

    def test_is_success(self):
        """AppConfig - Check If Success"""
        assert self._config.is_success

    def test_mark_partial(self):
        """AppConfig - Mark Partial"""
        self._config.mark_partial()
        assert self._config.current_state == 'partial'

    def test_mark_running(self):
        """AppConfig - Mark Running"""
        self._config.mark_running()
        assert self._config.current_state == 'running'

    def test_mark_success(self):
        """AppConfig - Mark Success"""
        self._config.mark_success()
        assert self._config.current_state == 'succeeded'

    def test_mark_failure(self):
        """AppConfig - Mark Failure"""
        self._config.mark_failure()
        assert self._config.current_state == 'failed'

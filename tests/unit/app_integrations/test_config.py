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
# pylint: disable=no-self-use,protected-access
from mock import patch
from nose.tools import assert_equal, assert_items_equal, raises

from app_integrations.config import AppConfig
from app_integrations.exceptions import AppIntegrationConfigError
from tests.unit.app_integrations import FUNCTION_NAME
from tests.unit.app_integrations.test_helpers import (
    get_mock_context,
    MockSSMClient,
    put_mock_params
)


@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient)
class TestAppIntegrationConfig(object):
    """Test class for AppIntegrationConfig"""

    def setup(self):
        """Setup before each method"""
        put_mock_params()

    def test_parse_context(self):
        """AppIntegrationConfig - Parse Context"""
        mock_context = get_mock_context()
        result = AppConfig._parse_context(mock_context)

        assert_equal(AppConfig.remaining_ms, mock_context.get_remaining_time_in_millis)
        assert_equal(AppConfig.remaining_ms(), 100)
        assert_equal(result['function_name'], FUNCTION_NAME)

    def test_load_config(self):
        """AppIntegrationConfig - Load config from SSM"""
        config = AppConfig.load_config(get_mock_context())
        assert_equal(len(config.keys()), 12)

    @raises(AppIntegrationConfigError)
    def test_load_config_bad(self):
        """AppIntegrationConfig - Load config from SSM, missing key"""
        config = AppConfig.load_config(get_mock_context())
        # Remove one of the required keys from the state
        del config['interval']
        config._validate_config()

    @raises(AppIntegrationConfigError)
    def test_load_config_empty(self):
        """AppIntegrationConfig - Load config from SSM, empty config"""
        config = AppConfig.load_config(get_mock_context())
        # Empty the config so the dict validates to False
        config.clear()
        config._validate_config()

    def test_get_param(self):
        """AppIntegrationConfig - Get parameter"""
        param, _ = AppConfig._get_parameters(['{}_config'.format(FUNCTION_NAME)])

        assert_items_equal(param['{}_config'.format(FUNCTION_NAME)].keys(),
                           {'cluster', 'app_name', 'type', 'prefix', 'interval'})

    @raises(AppIntegrationConfigError)
    def test_get_param_bad_value(self):
        """AppIntegrationConfig - Get parameter, bad json value"""
        config_name = '{}_config'.format(FUNCTION_NAME)
        MockSSMClient._PARAMETERS[config_name] = 'bad json string'
        AppConfig._get_parameters([config_name])

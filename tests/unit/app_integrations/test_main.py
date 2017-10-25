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
# pylint: disable=protected-access
from mock import call, patch

from nose.tools import assert_equal, raises

import app_integrations
from app_integrations.main import handler
from app_integrations.config import AppConfig
from app_integrations.exceptions import (
    AppIntegrationConfigError,
    AppIntegrationException
)

from tests.unit.app_integrations.test_helpers import (
    get_mock_context,
    get_valid_config_dict,
    MockSSMClient
)


@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient(suppress_params=True))
@raises(AppIntegrationConfigError)
def test_handler():
    """App Integration - Test Handler"""
    handler(None, get_mock_context())


@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient(suppress_params=True))
@raises(AppIntegrationException)
@patch('app_integrations.config.AppConfig.mark_failure')
@patch('app_integrations.config.AppConfig.load_config')
def test_handler_bad_type(config_mock, failure_mock):
    """App Integration - Test Handler, Bad Service Type"""
    base_config = get_valid_config_dict('duo_auth')
    base_config.update({'type': 'bad_type', 'current_state': 'running'})
    config_mock.return_value = AppConfig(base_config)
    handler(None, get_mock_context())

    failure_mock.assert_called()


@patch('app_integrations.config.AppConfig.mark_failure')
@patch('app_integrations.config.AppConfig.load_config')
@patch('app_integrations.apps.app_base.AppIntegration.gather')
def test_handler_success(gather_mock, config_mock, failure_mock):
    """App Integration - Test Handler, Success"""
    base_config = get_valid_config_dict('duo_auth')
    config_mock.return_value = AppConfig(base_config)
    gather_mock.return_value = None
    handler(None, get_mock_context())

    failure_mock.assert_not_called()


@patch('logging.Logger.error')
def test_init_logging_bad(log_mock):
    """App Integration - Logging, Bad Level"""
    with patch.dict('os.environ', {'LOGGER_LEVEL': 'IFNO'}):
        # Force reload the shared package to trigger the init
        reload(app_integrations)

        message = str(call('Defaulting to INFO logging: %s',
                           ValueError('Unknown level: \'IFNO\'',)))

        assert_equal(str(log_mock.call_args_list[0]), message)

@patch('logging.Logger.setLevel')
def test_init_logging_int_level(log_mock):
    """App Integration - Logging, Integer Level"""
    with patch.dict('os.environ', {'LOGGER_LEVEL': '10'}):
        # Force reload the shared package to trigger the init
        reload(app_integrations)

        log_mock.assert_called_with(10)

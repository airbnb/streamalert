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
# pylint: disable=abstract-class-instantiated,protected-access,no-self-use
from mock import Mock, patch

from botocore.exceptions import ClientError
from nose.tools import (
    assert_equal,
    assert_false,
    assert_is_none,
    assert_is_not_none,
    assert_items_equal,
    assert_true,
    raises
)
from requests.exceptions import ConnectTimeout

from app_integrations.apps.app_base import AppIntegration, StreamAlertApp
from app_integrations.batcher import Batcher
from app_integrations.config import AppConfig
from app_integrations.exceptions import AppIntegrationConfigError, AppIntegrationException
from tests.unit.app_integrations.test_helpers import (
    get_valid_config_dict,
    MockLambdaClient,
    MockSSMClient
)

def test_get_all_apps():
    """App Integration - App Base, Get All Apps"""
    expected_apps = {
        'box_admin_events',
        'duo_admin',
        'duo_auth',
        'gsuite_admin',
        'gsuite_calendar',
        'gsuite_drive',
        'gsuite_gplus',
        'gsuite_groups',
        'gsuite_login',
        'gsuite_mobile',
        'gsuite_rules',
        'gsuite_saml',
        'gsuite_token',
        'onelogin_events'
    }

    apps = StreamAlertApp.get_all_apps()
    assert_items_equal(expected_apps, apps)


def test_get_app():
    """App Integration - App Base, Get App"""
    config = AppConfig(get_valid_config_dict('duo_auth'))
    app = StreamAlertApp.get_app(config)
    assert_is_not_none(app)


@raises(AppIntegrationException)
def test_get_app_exception_type():
    """App Integration - App Base, Get App Exception for No 'type'"""
    config = AppConfig(get_valid_config_dict('duo_auth'))
    del config['type']
    StreamAlertApp.get_app(config)


@raises(AppIntegrationException)
def test_get_app_exception_invalid():
    """App Integration - App Base, Get App Exception for Invalid Service"""
    config = AppConfig(get_valid_config_dict('duo_auth'))
    config['type'] = 'bad_service_type'
    StreamAlertApp.get_app(config)


# Patch the required_auth_info method with values that a subclass _would_ return
TEST_AUTH_KEYS = {'api_hostname', 'integration_key', 'secret_key'}

@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient())
@patch.object(AppIntegration, 'type', Mock(return_value='type'))
@patch.object(AppIntegration, 'required_auth_info', Mock(return_value=TEST_AUTH_KEYS))
@patch.object(Batcher, 'LAMBDA_CLIENT', MockLambdaClient)
class TestAppIntegration(object):
    """Test class for the AppIntegration"""

    @patch.object(AppIntegration, 'type', Mock(return_value='type'))
    def __init__(self):
        self._app = None

    # Remove all abstractmethods so we can instantiate AppIntegration for testing
    # Also patch some abstractproperty attributes
    @patch.object(AppIntegration, '__abstractmethods__', frozenset())
    def setup(self):
        """Setup before each method"""
        self._app = AppIntegration(AppConfig(get_valid_config_dict('duo_admin'), None))

    @patch('logging.Logger.debug')
    def test_no_sleep(self, log_mock):
        """App Integration - App Base, No Sleep on First Poll"""
        self._app._sleep()
        log_mock.assert_called_with('Skipping sleep for first poll')

    @patch('time.sleep')
    @patch('app_integrations.apps.app_base.AppIntegration._sleep_seconds', Mock(return_value=1))
    def test_sleep(self, time_mock):
        """App Integration - App Base, Sleep"""
        self._app._poll_count = 1
        self._app._sleep()
        time_mock.assert_called_with(1)

    def test_validate_auth_(self):
        """App Integration - Validate Authentication Info"""
        assert_is_none(self._app._validate_auth())

    @raises(AppIntegrationConfigError)
    def test_validate_auth_empty(self):
        """App Integration - Validate Authentication Info, No Config Exception"""
        self._app._config.clear()
        self._app._validate_auth()

    @raises(AppIntegrationConfigError)
    def test_validate_auth_no_auth(self):
        """App Integration - Validate Authentication Info, No Auth Exception"""
        del self._app._config['auth']
        self._app._validate_auth()

    @raises(AppIntegrationConfigError)
    def test_validate_auth_missing_auth(self):
        """App Integration - Validate Authentication Info, Missing Auth Key Exception"""
        with patch.object(AppIntegration, 'required_auth_info') as auth_keys_mock:
            auth_keys_mock.return_value = {'new_auth_key'}
            self._app._validate_auth()

    def test_check_http_response_good(self):
        """App Integration - Check HTTP Response, Success"""
        response = Mock(status_code=200)
        assert_true(self._app._check_http_response(response))

    @patch('logging.Logger.error')
    def test_check_http_response_bad(self, log_mock):
        """App Integration - Check HTTP Response, Failure"""
        response = Mock(status_code=404, content='hey')

        # Check to make sure this resulted in a return of False
        assert_false(self._app._check_http_response(response))

        # Make sure the logger was called with the proper info
        log_mock.assert_called_with('HTTP request failed for service \'%s\': [%d] %s',
                                    'type', 404, 'hey')

    def test_initialize(self):
        """App Integration - Initialize, Valid"""
        assert_true(self._app._initialize())

    @patch('logging.Logger.error')
    def test_initialize_running(self, log_mock):
        """App Integration - Initialize, Already Running"""
        self._app._config['current_state'] = 'running'
        assert_false(self._app._initialize())
        log_mock.assert_called_with('App already running for service \'%s\'.', 'type')

    @patch('logging.Logger.error')
    def test_initialize_partial(self, log_mock):
        """App Integration - Initialize, Partial Execution"""
        self._app._config['current_state'] = 'partial'
        assert_false(self._app._initialize())
        log_mock.assert_called_with('App in partial execution state for service \'%s\'.', 'type')

    def test_finalize(self):
        """App Integration - Finalize, Valid"""
        test_new_time = 50000000
        self._app._last_timestamp = test_new_time
        self._app._finalize()
        assert_equal(self._app._config.last_timestamp, test_new_time)

    @patch('boto3.client', Mock(return_value=MockLambdaClient()))
    @patch('app_integrations.config.AppConfig.mark_success')
    def test_finalize_more_logs(self, config_mock):
        """App Integration - Finalize, More Logs"""
        self._app._more_to_poll = True
        self._app._finalize()

        config_mock.assert_not_called()

    @raises(ClientError)
    @patch('boto3.client', Mock(return_value=MockLambdaClient()))
    def test_finalize_more_logs_error(self):
        """App Integration - Finalize, More Logs"""
        MockLambdaClient._raise_exception = True
        self._app._more_to_poll = True
        self._app._finalize()

    @patch('logging.Logger.error')
    def test_finalize_zero_time(self, log_mock):
        """App Integration - Finalize, Zero Time Error"""
        self._app._finalize()
        log_mock.assert_called_with('Ending last timestamp is 0. This should not happen and '
                                    'is likely due to the subclass not setting this value.')

    @patch('logging.Logger.error')
    def test_finalize_same_time(self, log_mock):
        """App Integration - Finalize, Same Time Error"""
        self._app._last_timestamp = self._app._config.start_last_timestamp
        self._app._finalize()
        log_mock.assert_called_with('Ending last timestamp is the same as '
                                    'the beginning last timestamp. This could occur if '
                                    'there were no logs collected for this execution.')

    @patch('logging.Logger.info')
    def test_gather_success(self, log_mock):
        """App Integration - Gather, Success"""
        with patch.object(AppIntegration, '_gather_logs') as subclass_gather_mock:
            subclass_gather_mock.return_value = ['log01', 'log02', 'log03']
            self._app._gather()
            log_mock.assert_called()
            assert_equal(log_mock.call_args_list[-1][0][0],
                         'Gather process for \'%s\' executed in %f seconds.')

    @patch('logging.Logger.error')
    def test_gather_no_logs(self, log_mock):
        """App Integration - Gather, No Logs"""
        with patch.object(AppIntegration, '_gather_logs') as subclass_gather_mock:
            subclass_gather_mock.return_value = []
            self._app._gather()
            log_mock.assert_called_with('Gather process for service \'%s\' was not able '
                                        'to poll any logs on poll #%d', 'type', 1)

    @patch('app_integrations.apps.app_base.AppIntegration._finalize')
    @patch('app_integrations.apps.app_base.AppIntegration._sleep_seconds', Mock(return_value=1))
    @patch('app_integrations.config.AppConfig.remaining_ms', Mock(return_value=5000))
    def test_gather_entry(self, finalize_mock):
        """App Integration - Gather, Entry Point"""
        self._app.gather()
        finalize_mock.assert_called()

    @patch('app_integrations.apps.app_base.AppIntegration._gather')
    @patch('app_integrations.apps.app_base.AppIntegration._sleep_seconds', Mock(return_value=1))
    @patch('app_integrations.config.AppConfig.remaining_ms',
           Mock(side_effect=[8000, 8000, 2000, 2000]))
    def test_gather_multiple(self, gather_mock):
        """App Integration - Gather, Entry Point, Multiple Calls"""
        # 3 == number of 'seconds' this ran for. This is compared against the remaining_ms mock
        gather_mock.side_effect = [3, 3]
        self._app._more_to_poll = True
        self._app.gather()
        assert_equal(gather_mock.call_count, 2)

    @patch('app_integrations.apps.app_base.AppIntegration._finalize')
    def test_gather_running(self, finalize_mock):
        """App Integration - Gather, Entry Point, Already Running"""
        self._app._config['current_state'] = 'running'
        self._app.gather()
        finalize_mock.assert_not_called()

    @patch('requests.get')
    def test_make_request_bad_response(self, requests_mock):
        """App Integration - Make Request, Bad Response"""
        failed_message = 'something went wrong'
        requests_mock.return_value = Mock(
            status_code=404,
            content=failed_message,
            json=Mock(return_value={'message': failed_message})
        )

        result, response = self._app._make_get_request('hostname', None, None)
        assert_false(result)
        assert_equal(response['message'], failed_message)

        # The .json should be called on the response once, to return the response.
        assert_equal(requests_mock.return_value.json.call_count, 1)

    @patch('requests.get')
    def test_make_request_timeout(self, requests_mock):
        """App Integration - Make Request, Timeout"""
        requests_mock.side_effect = ConnectTimeout(None, response='too slow')
        result, response = self._app._make_get_request('hostname', None, None)
        assert_false(result)
        assert_is_none(response)

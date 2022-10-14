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
import os
from unittest.mock import Mock, call, patch

import pytest
import requests
from botocore.exceptions import ClientError
from moto import mock_ssm
from requests.exceptions import ConnectTimeout

from streamalert.apps import StreamAlertApp
from streamalert.apps._apps.duo import DuoAuthApp
from streamalert.apps.app_base import (AppIntegration, _report_time,
                                       safe_timeout)
from streamalert.apps.exceptions import AppException
from tests.unit.streamalert.apps.test_helpers import get_event, put_mock_params
from tests.unit.streamalert.shared.test_config import get_mock_lambda_context


class TestStreamAlertApp:
    """Test class for the StreamAlertApp"""
    # pylint: disable=no-self-use

    def test_get_all_apps(self):
        """StreamAlertApp - Get All Apps"""
        expected_apps = {
            'box_admin_events',
            'duo_admin',
            'duo_auth',
            'gsuite_access_transparency',
            'gsuite_admin',
            'gsuite_calendar',
            'gsuite_drive',
            'gsuite_gcp',
            'gsuite_gplus',
            'gsuite_groups',
            'gsuite_groups_enterprise',
            'gsuite_login',
            'gsuite_meet',
            'gsuite_mobile',
            'gsuite_rules',
            'gsuite_saml',
            'gsuite_token',
            'gsuite_user_accounts',
            'intercom_admin_activity_logs',
            'onelogin_events',
            'salesforce_console',
            'salesforce_login',
            'salesforce_loginas',
            'salesforce_report',
            'salesforce_reportexport',
            'slack_access',
            'slack_integration',
            'aliyun_actiontrail'
        }

        assert expected_apps == set(StreamAlertApp.get_all_apps())

    @patch('streamalert.apps.app_base.Batcher', Mock())
    def test_get_app(self):
        """StreamAlertApp - Get App"""
        assert StreamAlertApp.get_app('duo_auth') == DuoAuthApp

    @pytest.mark.xfail(raises=AppException)
    def test_get_app_invalid_type(self):
        """StreamAlertApp - Get App, Invalid Type"""
        StreamAlertApp.get_app('bad_app')


@mock_ssm
@patch.object(AppIntegration, 'type', Mock(return_value='type'))
class TestAppIntegration:
    """Test class for the AppIntegration"""
    # pylint: disable=protected-access

    # Remove all abstractmethods so we can instantiate AppIntegration for testing
    @patch.object(AppIntegration, '__abstractmethods__', frozenset())
    @patch('streamalert.apps.app_base.Batcher', Mock())
    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup before each method"""
        # pylint: disable=abstract-class-instantiated,attribute-defined-outside-init
        self._test_app_name = 'test_app'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._app = AppIntegration(self._event, self._context)

    @patch('logging.Logger.debug')
    def test_no_sleep(self, log_mock):
        """App Integration - App Base, No Sleep on First Poll"""
        self._app._sleep()
        log_mock.assert_called_with('Skipping sleep for first poll')

    @patch('time.sleep')
    @patch('streamalert.apps.app_base.AppIntegration._sleep_seconds', Mock(return_value=1))
    def test_sleep(self, time_mock):
        """App Integration - App Base, Sleep"""
        self._app._poll_count = 1
        self._app._sleep()
        time_mock.assert_called_with(1)

    def test_check_http_response_good(self):
        """App Integration - Check HTTP Response, Success"""
        response = Mock(status_code=200)
        assert self._app._check_http_response(response)

    @patch('logging.Logger.info')
    @patch('streamalert.apps.app_base.time')
    def test_report_time(self, time_mock, log_mock):
        """App Integration - Report Time"""
        # pylint: disable=no-self-use
        time_mock.time.side_effect = [100.0, 300.0]

        @_report_time
        def _test():
            pass

        assert _test() == 200.0
        log_mock.assert_called_with('[%s] Function executed in %.4f seconds.', '_test', 200.0)

    def test_safe_timeout(self):
        """App Integration - Safe Timeout"""
        # pylint: disable=no-self-use
        @safe_timeout
        def _test():
            raise ConnectTimeout(response='too slow')
        assert _test() == (False, None)

    @patch('streamalert.apps.app_base.AppIntegration._required_auth_info')
    def test_required_auth_info(self, auth_mock):
        """App Integration - Required Auth Info"""
        expected_result = {'host': 'host_name'}
        auth_mock.return_value = expected_result
        assert self._app.required_auth_info() == expected_result

        auth_mock.return_value = None
        assert self._app.required_auth_info() == {}

    @patch('logging.Logger.error')
    def test_check_http_response_bad(self, log_mock):
        """App Integration - Check HTTP Response, Failure"""
        response = Mock(status_code=404, content='hey')

        # Check to make sure this resulted in a return of False
        assert not self._app._check_http_response(response)

        # Make sure the logger was called with the proper info
        log_mock.assert_called_with('[%s] HTTP request failed: [%d] %s', self._app, 404, 'hey')

    def test_initialize(self):
        """App Integration - Initialize, Valid"""
        assert self._app._initialize()

    @patch('logging.Logger.warning')
    def test_initialize_running(self, log_mock):
        """App Integration - Initialize, Already Running"""
        self._app._config.current_state = 'running'
        assert not self._app._initialize()
        log_mock.assert_called_with('[%s] App already running', self._app)

    @patch('logging.Logger.error')
    def test_initialize_partial(self, log_mock):
        """App Integration - Initialize, Partial Execution"""
        self._app._config.current_state = 'partial'
        assert not self._app._initialize()
        log_mock.assert_called_with('[%s] App in partial execution state, exiting', self._app)

    @patch('streamalert.apps.config.AppConfig.mark_success')
    def test_finalize(self, mark_mock):
        """App Integration - Finalize, Valid"""
        test_new_time = 50000000
        self._app._last_timestamp = test_new_time
        self._app._finalize()
        assert self._app._config.last_timestamp == test_new_time
        mark_mock.assert_called()

    @patch('streamalert.apps.app_base.AppIntegration._invoke_successive_app')
    def test_finalize_more_logs_error(self, invoke_mock):
        """App Integration - Finalize, More Logs"""
        self._app._more_to_poll = True
        self._app._finalize()
        invoke_mock.assert_called()

    @patch('logging.Logger.error')
    def test_finalize_zero_time(self, log_mock):
        """App Integration - Finalize, Zero Time Error"""
        self._app._finalize()
        log_mock.assert_called_with('Ending last timestamp is 0. This should not happen and '
                                    'is likely due to the subclass not setting this value.')

    @patch('logging.Logger.info')
    def test_finalize_same_time(self, log_mock):
        """App Integration - Finalize, Same Time Error"""
        self._app._last_timestamp = self._app._config.start_last_timestamp
        self._app._finalize()
        calls = [
            call('Ending last timestamp is the same as '
                 'the beginning last timestamp. This could occur if '
                 'there were no logs collected for this execution.'),
            call('[%s] App complete; gathered %d logs in %d polls.', self._app, 0, 0)
        ]
        log_mock.assert_has_calls(calls)

    @pytest.mark.xfail(raises=ClientError)
    @patch('boto3.client')
    @patch('logging.Logger.error')
    def test_invoke_successive_app_exception(self, log_mock, boto_mock):
        """App Integration - Invoke Successive App, Exception"""
        err = ClientError({'Error': {'Code': 'TEST', 'Message': 'bad'}}, 'Invoke')
        boto_mock.return_value.invoke.side_effect = err
        self._app._invoke_successive_app()
        log_mock.assert_called_with(
            'An error occurred while invoking a subsequent app function (\'%s:%s\'). Error is: %s',
            self._test_app_name,
            'production',
            'bad'
        )

    @patch('boto3.client')
    @patch('logging.Logger.info')
    def test_invoke_successive_app(self, log_mock, boto_mock):
        """App Integration - Invoke Successive App"""
        boto_mock.return_value.invoke.return_value = {'ResponseMetadata': {'RequestId': 'foobar'}}
        self._app._invoke_successive_app()
        boto_mock.return_value.invoke.assert_called()
        log_mock.assert_called_with(
            'Invoking successive apps function \'%s\' with Lambda request ID \'%s\'',
            self._test_app_name,
            'foobar'
        )

    @patch('requests.get')
    def test_make_get_request_bad_response(self, requests_mock):
        """App Integration - Make Get Request, Bad Response"""
        failed_message = 'something went wrong'
        requests_mock.return_value = Mock(
            status_code=404,
            content=failed_message,
            json=Mock(return_value={'message': failed_message})
        )

        result, response = self._app._make_get_request('hostname', None, None)
        assert not result
        assert response['message'] == failed_message

        # The .json should be called on the response once, to return the response.
        assert requests_mock.return_value.json.call_count == 1

    @patch('requests.post')
    def test_make_post_request_json(self, requests_mock):
        """App Integration - Make Post Request, With JSON"""
        message = {'data': 'test_data'}
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=message)
        )
        args = 'hostname'
        result, response = self._app._make_post_request(args, None, None)
        assert result
        kwargs = {'headers': None, 'json': None, 'timeout': 3.05}
        requests_mock.assert_called_with(args, **kwargs)
        assert response == message

        # The .json should be called on the response once, to return the response.
        assert requests_mock.return_value.json.call_count == 1

    @patch('requests.post')
    def test_make_post_request_non_json(self, requests_mock):
        """App Integration - Make Post Request, Not JSON"""
        message = {'data': 'test_data'}
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=message)
        )
        args = 'hostname'
        result, response = self._app._make_post_request(args, None, None, False)
        assert result
        kwargs = {'headers': None, 'data': None, 'timeout': 3.05}
        requests_mock.assert_called_with(args, **kwargs)
        assert response == message

        # The .json should be called on the response once, to return the response.
        assert requests_mock.return_value.json.call_count == 1

    @patch('logging.Logger.error')
    def test_gather_no_logs(self, log_mock):
        """App Integration - Gather, No Logs"""
        with patch.object(AppIntegration, '_gather_logs') as subclass_gather_mock:
            subclass_gather_mock.return_value = []
            result = self._app._gather()
            assert isinstance(result, float)
            log_mock.assert_called_with(
                '[%s] Gather process was not able to poll any logs on poll #%d', self._app, 1
            )

    @patch('logging.Logger.info')
    @patch('streamalert.apps.app_base.time')
    def test_gather_success(self, time_mock, log_mock):
        """App Integration - Gather, Success"""
        time_mock.time.side_effect = [100.0, 300.0]
        with patch.object(AppIntegration, '_gather_logs') as subclass_gather_mock:
            subclass_gather_mock.return_value = ['log01', 'log02', 'log03']
            self._app._gather()
            assert self._app._gathered_log_count == 3
            log_mock.assert_called_with(
                '[%s] Function executed in %.4f seconds.', '_gather', 200.0
            )

    @patch('streamalert.apps.app_base.AppIntegration._finalize')
    @patch('streamalert.apps.app_base.AppIntegration._sleep_seconds', Mock(return_value=1))
    @patch('streamalert.apps.config.AppConfig.remaining_ms', Mock(return_value=5000))
    def test_gather_entry(self, finalize_mock):
        """App Integration - Gather, Entry Point"""
        self._app.gather()
        finalize_mock.assert_called()

    @patch('streamalert.apps.app_base.AppIntegration._gather')
    @patch('streamalert.apps.app_base.AppIntegration._sleep_seconds', Mock(return_value=1))
    @patch('streamalert.apps.config.AppConfig.remaining_ms',
           Mock(side_effect=[8000, 8000, 2000, 2000]))
    def test_gather_multiple(self, gather_mock):
        """App Integration - Gather, Entry Point, Multiple Calls"""
        # 3 == number of 'seconds' this ran for. This is compared against the remaining_ms mock
        gather_mock.side_effect = [3, 3]
        self._app._more_to_poll = True
        self._app.gather()
        assert gather_mock.call_count == 2

    @patch('streamalert.apps.app_base.AppIntegration._finalize')
    def test_gather_running(self, finalize_mock):
        """App Integration - Gather, Entry Point, Already Running"""
        self._app._config.current_state = 'running'
        self._app.gather()
        finalize_mock.assert_not_called()

    @patch('requests.sessions.Session.request')
    def test_make_post_request_gateway_timeout(self, requests_mock):
        """App Integration - Make Post Request when gateway timed out"""
        # set the return value to an empty response
        # the reponse's content defaults to None, which returns an empty str
        requests_mock.return_value = requests.Response()

        # need to set status_code in the response
        requests_mock.return_value.status_code = 504

        result, response = self._app._make_post_request('', None, None, False)
        assert not result
        assert response is None

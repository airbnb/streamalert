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
import collections
import os
from unittest.mock import Mock, patch

from moto import mock_ssm

from streamalert.apps._apps.onelogin import OneLoginApp
from tests.unit.streamalert.apps.test_helpers import get_event, put_mock_params
from tests.unit.streamalert.shared.test_config import get_mock_lambda_context


@mock_ssm
@patch.object(OneLoginApp, 'type', Mock(return_value='type'))
class TestOneLoginApp:
    """Test class for the OneLoginApp"""
    # pylint: disable=protected-access

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup before each method"""
        # pylint: disable=attribute-defined-outside-init
        self._test_app_name = 'onelogin'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._app = OneLoginApp(self._event, self._context)

    def set_config_values(self, region, client_id, client_secret):
        """Helper function to setup the auth values"""
        self._app._config.auth['region'] = region
        self._app._config.auth['client_id'] = client_id
        self._app._config.auth['client_secret'] = client_secret

    @patch('requests.post')
    def test_generate_headers_bad_response(self, requests_mock):
        """OneLoginApp - Generate Headers, Bad Response"""
        self.set_config_values('us', 'bad_id', 'bad_secret')
        requests_mock.return_value = Mock(
            status_code=404,
            json=Mock(return_value={'message': 'something went wrong'})
        )
        assert not self._app._generate_headers()

    @patch('requests.post')
    def test_generate_headers_empty_response(self, requests_mock):
        """OneLoginApp - Generate Headers, Empty Response"""
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=None)
        )
        assert not self._app._generate_headers()

    @patch('requests.post')
    def test_generate_headers(self, requests_mock):
        """OneLoginApp - Generate Headers"""
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'access_token': 'this_is_a_token'})
        )
        self._app._generate_headers()
        assert self._app._auth_headers['Authorization'] == 'bearer:this_is_a_token'

    def test_sleep(self):
        """OneLoginApp - Sleep Seconds"""
        self._app._poll_count = 1
        assert self._app._sleep_seconds() == 0
        self._app._poll_count = 200
        assert self._app._sleep_seconds() == 0

    def test_required_auth_info(self):
        """OneLoginApp - Required Auth Info"""
        assert collections.Counter(list(self._app.required_auth_info().keys())) == collections.Counter(
            {'region', 'client_secret', 'client_id'})

    @staticmethod
    def _get_sample_events(count, next_link):
        """Helper function for returning sample onelogin events"""
        event = {
            'id': 123,
            'created_at': '2017-10-05T18:11:32Z',
            'account_id': 1234,
            'user_id': 321,
            'event_type_id': 4321,
            'notes': 'Notes',
            'ipaddr': '0.0.0.0',  # nosec
            'actor_user_id': 987,
            'assuming_acting_user_id': 654,
            'role_id': 456,
            'app_id': 123456,
            'group_id': 98765,
            'otp_device_id': 11111,
            'policy_id': 22222,
            'actor_system': 'System',
            'custom_message': 'Message',
            'role_name': 'Role',
            'app_name': 'App Name',
            'group_name': 'Group Name',
            'actor_user_name': '',
            'user_name': 'username',
            'policy_name': 'Policy Name',
            'otp_device_name': 'OTP Device Name',
            'operation_name': 'Operation Name',
            'directory_sync_run_id': 7777,
            'directory_id': 6666,
            'resolution': 'Resolved',
            'client_id': 11223344,
            'resource_type_id': 44332211,
            'error_description': 'ERROR ERROR'
        }
        data = [event] * count

        return {'data': data, 'pagination': {'next_link': next_link}}

    def test_get_onelogin_events_no_headers(self):
        """OneLoginApp - Get OneLogin Events, No Headers"""
        assert not self._app._get_onelogin_events()

    @patch('requests.get')
    def test_get_onelogin_events_bad_response(self, requests_mock):
        """OneLoginApp - Get OneLogin Events, Bad Response"""
        self._app._auth_headers = True
        requests_mock.return_value = Mock(
            status_code=404,
            json=Mock(return_value={'message': 'something went wrong'})
        )
        assert not self._app._get_onelogin_events()

    @patch('requests.get')
    def test_get_onelogin_events_empty_response(self, requests_mock):
        """OneLoginApp - Get OneLogin Events, Empty Response"""
        self._app._auth_headers = True
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=None)
        )
        assert not self._app._get_onelogin_events()

    @patch('requests.get')
    def test_get_onelogin_events_rate_limited(self, requests_mock):
        """OneLoginApp - Get OneLogin Events, Rate Limited"""
        self._app._auth_headers = True
        self._app._rate_limit_sleep = 1
        err_limit_response = Mock(
            status_code=400,
            json=Mock(return_value={
                'message': 'something went wrong',
                'status': {'code': 400, 'message': 'rate_limit_exceeded'}
            })
        )
        ok_limit_response = Mock(
            status_code=200,
            json=Mock(return_value={
                'data': {'X-RateLimit-Reset': 123}
            })
        )
        requests_mock.side_effect = [err_limit_response, ok_limit_response]
        assert not self._app._get_onelogin_events()
        assert self._app._rate_limit_sleep == 123

    @patch('requests.get')
    def test_get_onelogin_events_empty_data(self, requests_mock):
        """OneLoginApp - Get OneLogin Events, Empty Data"""
        self._app._auth_headers = True
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'data': [], 'pagination': {'next_link': 'not'}})
        )
        assert not self._app._get_onelogin_events()

    @patch('requests.post')
    def test_gather_logs_no_headers(self, requests_mock):
        """OneLoginApp - Gather Events Entry Point, No Headers"""
        self.set_config_values('us', 'bad_id', 'bad_secret')
        requests_mock.return_value = Mock(
            status_code=404,
            json=Mock(return_value={'message': 'something went wrong'})
        )
        assert not self._app._gather_logs()

    @patch('requests.get')
    def test_gather_logs_no_pagination(self, requests_mock):
        """OneLoginApp - Gather Events Entry Point, No Pagination"""
        logs = self._get_sample_events(5, None)
        self._app._auth_headers = True
        self._app._next_page_url = None
        self._app._last_timestamp = 1507698237
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=[logs])
        )
        events = self._app._gather_logs()
        assert len(logs['data']) == len(events)
        assert logs['pagination']['next_link'] == self._app._next_page_url

    @patch('requests.get')
    def test_get_onelogin_get_events_without_pagination(self, requests_mock):
        """OneLoginApp - Get Events Without Pagination"""
        pagination = None
        logs = self._get_sample_events(2, pagination)
        self._app._auth_headers = True
        self._app._next_page_url = pagination
        self._app._last_timestamp = 1507698237
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=[logs])
        )
        events = self._app._get_onelogin_events()
        assert len(logs['data']) == len(events)
        assert logs['pagination']['next_link'] == self._app._next_page_url

    @patch('requests.get')
    def test_get_onelogin_get_events_with_pagination(self, requests_mock):
        """OneLoginApp - Get Events With Pagination"""
        next_link = 'https://next_link'
        logs = self._get_sample_events(3, next_link)
        self._app._auth_headers = True
        self._app._next_page_url = next_link
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=[logs])
        )
        events = self._app._get_onelogin_events()
        assert len(logs['data']) == len(events)
        assert logs['pagination']['next_link'] == self._app._next_page_url

    @patch('requests.get')
    def test_set_onelogin_rate_limit_sleep(self, requests_mock):
        """OneLoginApp - Set OneLogin Rate Limit Sleep"""
        self._app._auth_headers = True
        self._app._rate_limit_sleep = 0
        new_rate_limit_sleep = 123
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'data': {'X-RateLimit-Reset': new_rate_limit_sleep}})
        )
        self._app._set_rate_limit_sleep()
        assert self._app._rate_limit_sleep == new_rate_limit_sleep

    def test_set_onelogin_rate_limit_sleep_no_headers(self):
        """OneLoginApp - Set OneLogin Rate Limit Sleep, No Headers"""
        self._app._auth_headers = None
        self._app._rate_limit_sleep = 1
        self._app._set_rate_limit_sleep()
        assert self._app._rate_limit_sleep == 0

    @patch('requests.get')
    def test_set_onelogin_rate_limit_sleep_bad_response(self, requests_mock):
        """OneLoginApp - Set OneLogin Rate Limit Sleep, Bad Response"""
        self._app._auth_headers = True
        self._app._rate_limit_sleep = 1
        requests_mock.return_value = Mock(
            status_code=403,
            json=Mock(return_value={'message': 'something went wrong'})
        )
        self._app._set_rate_limit_sleep()
        assert self._app._rate_limit_sleep == 0

    @patch('requests.get')
    def test_set_onelogin_rate_limit_sleep_empty_response(self, requests_mock):
        """OneLoginApp - Set OneLogin Rate Limit Sleep, Empty Response"""
        self._app._auth_headers = True
        self._app._rate_limit_sleep = 1
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=None)
        )
        self._app._set_rate_limit_sleep()
        assert self._app._rate_limit_sleep == 0

    def test_onelogin_events_endpoint(self):
        """OneLoginApp - Verify Events Endpoint"""
        assert self._app._events_endpoint() == 'https://api.us.onelogin.com/api/1/events'

    def test_onelogin_token_endpoint(self):
        """OneLoginApp - Verify Token Endpoint"""
        assert (self._app._token_endpoint() ==
                'https://api.us.onelogin.com/auth/oauth2/v2/token')


def test_onelogin_events_type():
    """OneLoginApp - Verify Events Type"""
    # pylint: disable=protected-access
    assert OneLoginApp._type() == 'events'


def test_onelogin_event_service():
    """OneLoginApp - Verify Service"""
    assert OneLoginApp.service() == 'onelogin'

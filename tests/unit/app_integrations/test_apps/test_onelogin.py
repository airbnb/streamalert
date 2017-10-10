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

from nose.tools import assert_equal, assert_false, assert_items_equal

from app_integrations.apps.onelogin import OneLoginApp
from app_integrations.config import AppConfig

from tests.unit.app_integrations.test_helpers import (
    get_valid_config_dict,
    MockSSMClient
)


@patch.object(OneLoginApp, 'type', Mock(return_value='type'))
@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient())
class TestOneLoginApp(object):
    """Test class for the OneLoginApp"""

    def __init__(self):
        self._app = None

    # Remove all abstractmethods so we can instantiate OneLoginApp for testing
    # Also patch some abstractproperty attributes
    @patch.object(OneLoginApp, '__abstractmethods__', frozenset())
    def setup(self):
        """Setup before each method"""
        self._app = OneLoginApp(AppConfig(get_valid_config_dict('onelogin')))

    def set_config_values(self, region, client_id, client_secret):
        """Helper function to setup the auth values"""
        self._app._config['auth']['region'] = region
        self._app._config['auth']['client_id'] = client_id
        self._app._config['auth']['client_secret'] = client_secret

    @patch('requests.post')
    def test_generate_headers_bad(self, requests_mock):
        """OneLoginApp - Generate Bad Headers, """
        self.set_config_values('us', 'bad_id', 'bad_secret')
        requests_mock.return_value = Mock(
            status_code=404,
            json=Mock(side_effect=[{'message': 'something went wrong'}])
        )
        assert_false(self._app._generate_headers())

    @patch('requests.post')
    def test_generate_headers_good(self, requests_mock):
        """OneLoginApp - Generate Good Headers, """
        self.set_config_values('us', 'good_id', 'good_secret')
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=[{'access_token': 'this_is_a_token'}])
        )
        self._app._generate_headers()
        assert_equal(self._app._auth_headers['Authorization'], 'bearer:this_is_a_token')

    def test_sleep(self):
        """OneLoginApp - Sleep Seconds"""
        self._app._poll_count = 1
        assert_equal(self._app._sleep_seconds(), 0)
        self._app._poll_count = 200
        assert_equal(self._app._sleep_seconds(), 0)

    def test_required_auth_info(self):
        """OneLoginApp - Required Auth Info"""
        assert_items_equal(self._app.required_auth_info().keys(),
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
            'ipaddr': '0.0.0.0',
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

    @patch('requests.get')
    def test_get_onelogin_events_no_headers(self, requests_mock):
        """OneLoginApp - Get OneLogin Events, No Headers"""
        assert_false(self._app._get_onelogin_events())
        requests_mock.assert_not_called()

    @patch('requests.get')
    def test_get_onelogin_events_bad_response(self, requests_mock):
        """OneLoginApp - Get OneLogin Events, Bad Response"""
        self.set_config_values('us', 'good_id', 'good_secret')
        requests_mock.return_value = Mock(
            status_code=404,
            json=Mock(side_effect=[{'message': 'something went wrong'}])
        )
        assert_false(self._app._get_onelogin_events())

    @patch('requests.get')
    def test_gather_logs(self, requests_mock):
        """OneLoginApp - Gather Events Entry Point"""
        log_count = 3
        logs = self._get_sample_events(log_count, False)
        self.set_config_values('us', 'good_id', 'good_secret')
        self._app._auth_headers = True
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=[{'response': logs}])
        )
        assert_equal(len(logs['data']), log_count)

    @patch('requests.get')
    def test_get_onelogin_get_events_without_pagination(self, requests_mock):
        """OneLoginApp - Get Events Without Pagination"""
        log_count = 2
        pagination = None
        logs = self._get_sample_events(log_count, pagination)
        self.set_config_values('us', 'good_id', 'good_secret')
        self._app._auth_headers = True
        self._app._next_page_url = pagination
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=[{'response': logs}])
        )
        assert_equal(len(logs['data']), log_count)
        assert_equal(logs['pagination']['next_link'], pagination)

    @patch('requests.get')
    def test_get_onelogin_get_events_with_pagination(self, requests_mock):
        """OneLoginApp - Get Events With Pagination"""
        log_count = 2
        next_link = 'https://next_link'
        logs = self._get_sample_events(log_count, next_link)
        self.set_config_values('us', 'good_id', 'good_secret')
        self._app._auth_headers = True
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=[{'response': logs}])
        )
        assert_equal(len(logs['data']), log_count)
        assert_equal(logs['pagination']['next_link'], next_link)

    def test_onelogin_events_endpoint(self):
        """OneLoginApp - Verify Events Endpoint"""
        self._app._config['auth']['region'] = 'us'
        assert_equal(self._app._events_endpoint(), 'https://api.us.onelogin.com/api/1/events')

    def test_onelogin_token_endpoint(self):
        """OneLoginApp - Verify Token Endpoint"""
        self._app._config['auth']['region'] = 'us'
        assert_equal(self._app._token_endpoint(),
                     'https://api.us.onelogin.com/auth/oauth2/v2/token')

def test_onelogin_events_type():
    """OneLoginApp - Verify Events Type"""
    assert_equal(OneLoginApp._type(), 'events')

def test_onelogin_event_service():
    """OneLoginApp - Verify Service"""
    assert_equal(OneLoginApp.service(), 'onelogin')

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
# pylint: disable=abstract-class-instantiated,protected-access,no-self-use,abstract-method,attribute-defined-outside-init
import json
from mock import Mock, mock_open, patch

from boxsdk.exception import BoxException
from nose.tools import assert_equal, assert_false, assert_items_equal, assert_true
from requests.exceptions import ConnectionError, Timeout

from app_integrations.apps.box import BoxApp
from app_integrations.config import AppConfig

from tests.unit.app_integrations.test_helpers import (
    get_valid_config_dict,
    MockSSMClient
)

@patch.object(BoxApp, 'type', Mock(return_value='type'))
@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient())
class TestBoxApp(object):
    """Test class for the BoxApp"""

    # Remove all abstractmethods so we can instantiate BoxApp for testing
    @patch.object(BoxApp, '__abstractmethods__', frozenset())
    def setup(self):
        """Setup before each method"""
        self._app = BoxApp(AppConfig(get_valid_config_dict('box_admin_events')))

    def test_sleep(self):
        """BoxApp - Sleep Seconds"""
        assert_equal(self._app._sleep_seconds(), 0)

    def test_required_auth_info(self):
        """BoxApp - Required Auth Info"""
        assert_items_equal(self._app.required_auth_info().keys(), {'keyfile'})

    @patch('app_integrations.apps.box.JWTAuth.from_settings_dictionary',
           Mock(return_value=True))
    def test_keyfile_validator(self):
        """BoxApp - Keyfile Validation, Success"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        data = {'test': 'keydata'}
        mocker = mock_open(read_data=json.dumps(data))
        with patch('__builtin__.open', mocker):
            loaded_keydata = validation_function('fakepath')
            assert_equal(loaded_keydata, data)

    @patch('app_integrations.apps.box.JWTAuth.from_settings_dictionary')
    def test_keyfile_validator_failure(self, cred_mock):
        """BoxApp - Keyfile Validation, Failure"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        cred_mock.return_value = False
        mocker = mock_open(read_data=json.dumps({'test': 'keydata'}))
        with patch('__builtin__.open', mocker):
            assert_false(validation_function('fakepath'))
            cred_mock.assert_called()

    @patch('app_integrations.apps.box.JWTAuth.from_settings_dictionary')
    def test_keyfile_validator_bad_json(self, cred_mock):
        """BoxApp - Keyfile Validation, Bad JSON"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        mocker = mock_open(read_data='invalid json')
        with patch('__builtin__.open', mocker):
            assert_false(validation_function('fakepath'))
            cred_mock.assert_not_called()

    @patch('app_integrations.apps.box.JWTAuth.from_settings_dictionary',
           Mock(return_value=True))
    def test_load_credentials(self):
        """BoxApp - Load Auth, Success"""
        assert_true(self._app._load_auth('fakedata'))

    @patch('app_integrations.apps.box.JWTAuth.from_settings_dictionary')
    def test_load_credentials_bad(self, cred_mock):
        """BoxApp - Load Auth, ValueError"""
        cred_mock.side_effect = ValueError('Bad things happened')
        assert_false(self._app._load_auth('fakedata'))

    @patch('app_integrations.apps.box.Client',
           Mock(return_value=True))
    @patch('app_integrations.apps.box.BoxApp._load_auth')
    def test_create_client(self, auth_mock):
        """BoxApp - Create Client, Success"""
        assert_true(self._app._create_client())
        auth_mock.assert_called_with(self._app._config.auth['keyfile'])

    @patch('logging.Logger.debug')
    def test_create_client_exists(self, log_mock):
        """BoxApp - Create Client, Exists"""
        self._app._client = True
        assert_true(self._app._create_client())
        log_mock.assert_called_with('Client already instantiated for %s', 'type')

    @patch('app_integrations.apps.box.BoxApp._load_auth',
           Mock(return_value=False))
    def test_create_client_fail_auth(self):
        """BoxApp - Create Client, Auth Failure"""
        assert_false(self._app._create_client())

    def test_gather_logs(self):
        """BoxApp - Gather Logs, Success"""
        with patch.object(self._app, '_client') as client_mock:
            payload = {
                'chunk_size': 10,
                'next_stream_position': '1152922976252290886',
                'entries': self._get_sample_logs(10)
            }
            client_mock.make_request.return_value.json.return_value = payload

            assert_equal(len(self._app._gather_logs()), 10)
            assert_equal(self._app._last_timestamp, '2017-10-27T12:31:22-07:00')

    @patch('app_integrations.apps.box.BoxApp._create_client',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_box_error(self, log_mock):
        """BoxApp - Gather Logs, BoxException"""
        with patch.object(self._app, '_client') as client_mock:
            client_mock.make_request.side_effect = BoxException('bad error')
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('Failed to get events for %s', 'type')

    @patch('app_integrations.apps.box.BoxApp._create_client',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_requests_error(self, log_mock):
        """BoxApp - Gather Logs, ConnectionError"""
        with patch.object(self._app, '_client') as client_mock:
            self._app._next_stream_position = 10241040195019
            client_mock.make_request.side_effect = ConnectionError(response='bad error')
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('Bad response received from host, will retry once')

    @patch('app_integrations.apps.box.BoxApp._create_client',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_requests_timeout(self, log_mock):
        """BoxApp - Gather Logs, Timeout"""
        with patch.object(self._app, '_client') as client_mock:
            client_mock.make_request.side_effect = Timeout(response='request timed out')
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('Request timed out for %s', 'type')

    @patch('app_integrations.apps.box.BoxApp._load_auth',
           Mock(return_value=False))
    def test_gather_logs_no_client(self):
        """BoxApp - Gather Logs, No Client"""
        with patch.object(self._app, '_client') as client_mock:
            self._app._client = False
            assert_false(self._app._gather_logs())
            client_mock.make_request.assert_not_called()

    @patch('app_integrations.apps.box.BoxApp._create_client',
           Mock(return_value=True))
    @patch('logging.Logger.error')
    def test_gather_logs_no_results(self, log_mock):
        """BoxApp - Gather Logs, No Results From API"""
        with patch.object(self._app, '_client') as client_mock:
            client_mock.make_request.return_value.json.return_value = None
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('No results received from the Box API request for %s',
                                        'type')

    @patch('app_integrations.apps.box.BoxApp._create_client',
           Mock(return_value=True))
    @patch('logging.Logger.info')
    def test_gather_logs_empty_items(self, log_mock):
        """BoxApp - Gather Logs, Empty Entries List"""
        with patch.object(self._app, '_client') as client_mock:
            payload = {
                'chunk_size': 0,
                'next_stream_position': '1152922976252290886',
                'entries': []
            }
            client_mock.make_request.return_value.json.return_value = payload
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('No events in response from the Box API request for %s',
                                        'type')

    @staticmethod
    def _get_sample_logs(count):
        """Helper function for returning sample Box admin event logs"""
        return [{
            'additional_details': None,
            'created_at': '2017-10-27T12:31:22-07:00',
            'created_by': {
                'id': '2710218233',
                'login': 'testemail@email.com',
                'name': 'User Name',
                'type': 'user'
            },
            'event_id': '0e0b8122-17ed-42ee-8a9d-d9a57bf8dd83',
            'event_type': 'ADD_LOGIN_ACTIVITY_DEVICE',
            'ip_address': '1.1.1.22',
            'session_id': None,
            'source': {
                'id': '2710218233',
                'login': 'testemail@email.com',
                'name': 'User Name',
                'type': 'user'
            },
            'type': 'event'
        } for _ in range(count)]

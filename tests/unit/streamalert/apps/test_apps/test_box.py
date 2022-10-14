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
import json
import os
from unittest.mock import Mock, call, mock_open, patch

import requests
from boxsdk.exception import BoxException
from moto import mock_ssm

from streamalert.apps._apps.box import BoxApp
from tests.unit.streamalert.apps.test_helpers import get_event, put_mock_params
from tests.unit.streamalert.shared.test_config import get_mock_lambda_context


@mock_ssm
@patch.object(BoxApp, 'type', Mock(return_value='type'))
class TestBoxApp:
    """Test class for the BoxApp"""
    # pylint: disable=protected-access,no-self-use

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup before each method"""
        # pylint: disable=attribute-defined-outside-init
        self._test_app_name = 'box_admin_events'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._app = BoxApp(self._event, self._context)

    def test_sleep(self):
        """BoxApp - Sleep Seconds"""
        assert self._app._sleep_seconds() == 0

    def test_required_auth_info(self):
        """BoxApp - Required Auth Info"""
        assert collections.Counter(
            list(
                self._app.required_auth_info().keys())) == collections.Counter(
            {'keyfile'})

    @patch('streamalert.apps._apps.box.JWTAuth.from_settings_dictionary', Mock())
    def test_keyfile_validator(self):
        """BoxApp - Keyfile Validation, Success"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        data = {'test': 'keydata'}
        mocker = mock_open(read_data=json.dumps(data))
        with patch('builtins.open', mocker):
            loaded_keydata = validation_function('fakepath')
            assert loaded_keydata == data

    @patch('streamalert.apps._apps.box.JWTAuth.from_settings_dictionary')
    def test_keyfile_validator_failure(self, cred_mock):
        """BoxApp - Keyfile Validation, Failure"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        cred_mock.return_value = False
        mocker = mock_open(read_data=json.dumps({'test': 'keydata'}))
        with patch('builtins.open', mocker):
            assert not validation_function('fakepath')
            cred_mock.assert_called()

    @patch('streamalert.apps._apps.box.JWTAuth.from_settings_dictionary')
    def test_keyfile_validator_bad_json(self, cred_mock):
        """BoxApp - Keyfile Validation, Bad JSON"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        mocker = mock_open(read_data='invalid json')
        with patch('builtins.open', mocker):
            assert not validation_function('fakepath')
            cred_mock.assert_not_called()

    @patch('streamalert.apps._apps.box.JWTAuth.from_settings_dictionary', Mock())
    def test_load_credentials(self):
        """BoxApp - Load Auth, Success"""
        assert self._app._load_auth('fakedata')

    @patch('streamalert.apps._apps.box.JWTAuth.from_settings_dictionary')
    def test_load_credentials_bad(self, cred_mock):
        """BoxApp - Load Auth, ValueError"""
        cred_mock.side_effect = ValueError('Bad things happened')
        assert not self._app._load_auth('fakedata')

    @patch('streamalert.apps._apps.box.BoxApp._load_auth')
    def test_create_client(self, auth_mock):
        """BoxApp - Create Client, Success"""
        assert self._app._create_client()
        auth_mock.assert_called_with(self._app._config.auth['keyfile'])

    @patch('logging.Logger.debug')
    def test_create_client_exists(self, log_mock):
        """BoxApp - Create Client, Exists"""
        self._app._client = True
        assert self._app._create_client()
        log_mock.assert_called_with('[%s] Client already instantiated', self._app)

    @patch('streamalert.apps._apps.box.BoxApp._load_auth', Mock(return_value=False))
    def test_create_client_fail_auth(self):
        """BoxApp - Create Client, Auth Failure"""
        assert not self._app._create_client()

    def test_gather_logs(self):
        """BoxApp - Gather Logs, Success"""
        with patch.object(self._app, '_client') as client_mock:
            client_mock.make_request.return_value.json.return_value = self._get_sample_payload(10)

            assert len(self._app._gather_logs()) == 10
            assert self._app._last_timestamp == '2017-10-27T12:31:22-07:00'

    @patch('streamalert.apps._apps.box.BoxApp._create_client', Mock())
    @patch('logging.Logger.exception')
    def test_gather_logs_box_error(self, log_mock):
        """BoxApp - Gather Logs, BoxException"""
        with patch.object(self._app, '_client') as client_mock:
            client_mock.make_request.side_effect = BoxException('bad error')
            assert not self._app._gather_logs()
            log_mock.assert_called_with('[%s] Failed to get events', self._app)

    @patch('streamalert.apps._apps.box.BoxApp._create_client', Mock())
    @patch('logging.Logger.exception')
    def test_gather_logs_requests_error(self, log_mock):
        """BoxApp - Gather Logs, requests.ConnectionError"""
        with patch.object(self._app, '_client') as client_mock:
            self._app._next_stream_position = 10241040195019
            client_mock.make_request.side_effect = requests.exceptions.ConnectionError(
                response='bad error'
            )
            assert not self._app._gather_logs()
            log_mock.assert_called_with('Bad response received from host, will retry once')

    @patch('streamalert.apps._apps.box.BoxApp._create_client', Mock())
    @patch('logging.Logger.exception')
    def test_gather_logs_requests_timeout_retry_fail(self, log_mock):
        """BoxApp - Gather Logs, Timeout Retry and Fail"""
        with patch.object(self._app, '_client') as client_mock:
            client_mock.make_request.side_effect = requests.exceptions.Timeout(
                response='request timed out'
            )
            assert not self._app._gather_logs()
            log_mock.assert_called_with('[%s] Request timed out', '_make_request')

    @patch('streamalert.apps._apps.box.BoxApp._create_client', Mock())
    @patch('logging.Logger.debug')
    def test_gather_logs_requests_timeout_retry_success(self, log_mock):
        """BoxApp - Gather Logs, Timeout Retry and Succeed"""
        with patch.object(self._app, '_client') as client_mock:
            # client_mock.make_request.return_value.json.return_value = None
            client_mock.make_request.side_effect = [
                requests.exceptions.Timeout(response='request timed out once'),
                requests.exceptions.Timeout(response='request timed out twice'),
                Mock(json=Mock(return_value=self._get_sample_payload(1))),
            ]
            assert bool(self._app._gather_logs())
            log_mock.assert_has_calls([
                call('Attempting new request with timeout: %0.2f seconds', 6.10),
                call('Attempting new request with timeout: %0.2f seconds', 12.20),
            ])

    @patch('streamalert.apps._apps.box.BoxApp._load_auth', Mock(return_value=False))
    def test_gather_logs_no_client(self):
        """BoxApp - Gather Logs, No Client"""
        with patch.object(self._app, '_client') as client_mock:
            self._app._client = False
            assert not self._app._gather_logs()
            client_mock.make_request.assert_not_called()

    @patch('streamalert.apps._apps.box.BoxApp._create_client', Mock())
    @patch('logging.Logger.error')
    def test_gather_logs_no_results(self, log_mock):
        """BoxApp - Gather Logs, No Results From API"""
        with patch.object(self._app, '_client') as client_mock:
            client_mock.make_request.return_value.json.return_value = None
            assert not self._app._gather_logs()
            log_mock.assert_called_with('[%s] No results received in request', self._app)

    @patch('streamalert.apps._apps.box.BoxApp._create_client', Mock())
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
            assert not self._app._gather_logs()
            log_mock.assert_called_with('[%s] No events found in result', self._app)

    def _get_sample_payload(self, count):
        return {
            'chunk_size': 10,
            'next_stream_position': '1152922976252290886',
            'entries': self._get_sample_logs(count)
        }

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

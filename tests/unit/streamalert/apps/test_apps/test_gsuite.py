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
import socket
import ssl
from datetime import datetime, timedelta
from unittest.mock import Mock, mock_open, patch

import googleapiclient
import pytest
from google.auth import exceptions
from moto import mock_ssm

from streamalert.apps._apps.gsuite import GSuiteReportsApp
from tests.unit.streamalert.apps.test_helpers import get_event, put_mock_params
from tests.unit.streamalert.shared.test_config import get_mock_lambda_context


@mock_ssm
@patch.object(GSuiteReportsApp, '_type', Mock(return_value='admin'))
@patch.object(GSuiteReportsApp, 'type', Mock(return_value='type'))
class TestGSuiteReportsApp:
    """Test class for the GSuiteReportsApp"""
    # pylint: disable=protected-access

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup before each method"""
        # pylint: disable=attribute-defined-outside-init
        self._test_app_name = 'gsuite_admin'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._app = GSuiteReportsApp(self._event, self._context)

    def test_sleep(self):
        """GSuiteReportsApp - Sleep Seconds"""
        assert self._app._sleep_seconds() == 0

    def test_required_auth_info(self):
        """GSuiteReportsApp - Required Auth Info"""
        assert collections.Counter(list(self._app.required_auth_info().keys())
                                   ) == collections.Counter({'delegation_email', 'keyfile'})

    @patch('google.oauth2.service_account.Credentials.from_service_account_info',
           Mock(return_value=True))
    def test_keyfile_validator(self):
        """GSuiteReportsApp - Keyfile Validation, Success"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        data = {'test': 'keydata'}
        mocker = mock_open(read_data=json.dumps(data))
        with patch('builtins.open', mocker):
            loaded_keydata = validation_function('fakepath')
            assert loaded_keydata == data

    @patch('google.oauth2.service_account.Credentials.from_service_account_info')
    def test_keyfile_validator_failure(self, cred_mock):
        """GSuiteReportsApp - Keyfile Validation, Failure"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        cred_mock.return_value = False
        mocker = mock_open(read_data=json.dumps({'test': 'keydata'}))
        with patch('builtins.open', mocker):
            assert not validation_function('fakepath')
            cred_mock.assert_called()

    @patch('google.oauth2.service_account.Credentials.from_service_account_info')
    def test_keyfile_validator_bad_json(self, cred_mock):
        """GSuiteReportsApp - Keyfile Validation, Bad JSON"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        mocker = mock_open(read_data='invalid json')
        with patch('builtins.open', mocker):
            assert not validation_function('fakepath')
            cred_mock.assert_not_called()

    @patch('google.oauth2.service_account.Credentials.from_service_account_info',
           Mock(return_value=True))
    def test_load_credentials(self):
        """GSuiteReportsApp - Load Credentials, Success"""
        assert self._app._load_credentials('fakedata')

    @patch('google.oauth2.service_account.Credentials.from_service_account_info')
    def test_load_credentials_bad(self, cred_mock):
        """GSuiteReportsApp - Load Credentials, ValueError"""
        cred_mock.side_effect = ValueError('Bad things happened')
        assert not self._app._load_credentials('fakedata')

    @patch('streamalert.apps._apps.gsuite.GSuiteReportsApp._load_credentials', Mock())
    @patch('streamalert.apps._apps.gsuite.googleapiclient.discovery.build')
    def test_create_service(self, build_mock):
        """GSuiteReportsApp - Create Service, Success"""
        build_mock.return_value.activities.return_value = True
        assert self._app._create_service()

    @patch('logging.Logger.debug')
    def test_create_service_exists(self, log_mock):
        """GSuiteReportsApp - Create Service, Exists"""
        self._app._activities_service = True
        assert self._app._create_service()
        log_mock.assert_called_with('[%s] Service already instantiated', self._app)

    @patch('streamalert.apps._apps.gsuite.GSuiteReportsApp._load_credentials',
           Mock(return_value=False))
    def test_create_service_fail_creds(self):
        """GSuiteReportsApp - Create Service, Credential Failure"""
        assert not self._app._create_service()

    @patch('streamalert.apps._apps.gsuite.GSuiteReportsApp._load_credentials', Mock())
    @patch('logging.Logger.exception')
    @patch('streamalert.apps._apps.gsuite.googleapiclient.discovery.build')
    def test_create_service_api_error(self, build_mock, log_mock):
        """GSuiteReportsApp - Create Service, Google API Error"""
        build_mock.side_effect = googleapiclient.errors.Error('This is bad')
        assert not self._app._create_service()
        log_mock.assert_called_with('[%s] Failed to build discovery service', self._app)

    @patch('streamalert.apps._apps.gsuite.GSuiteReportsApp._load_credentials', Mock())
    @patch('logging.Logger.exception')
    @patch('streamalert.apps._apps.gsuite.googleapiclient.discovery.build')
    def test_create_service_ssl_error(self, build_mock, log_mock):
        """GSuiteReportsApp - Create Service, SSL Handshake Error"""
        build_mock.side_effect = ssl.SSLError('_ssl.c:574: The handshake operation timed out')
        assert not self._app._create_service()
        log_mock.assert_called_with('[%s] Failed to build discovery service', self._app)

    @patch('streamalert.apps._apps.gsuite.GSuiteReportsApp._load_credentials', Mock())
    @patch('logging.Logger.exception')
    @patch('streamalert.apps._apps.gsuite.googleapiclient.discovery.build')
    def test_create_service_socket_error(self, build_mock, log_mock):
        """GSuiteReportsApp - Create Service, Socket Timeout"""
        build_mock.side_effect = socket.timeout('timeout: timed out')
        assert not self._app._create_service()
        log_mock.assert_called_with('[%s] Failed to build discovery service', self._app)

    def test_gather_logs(self):
        """GSuiteReportsApp - Gather Logs, Success"""
        with patch.object(self._app, '_activities_service') as service_mock:
            payload = {
                'kind': 'reports#auditActivities',
                'nextPageToken': 'the next page\'s token',
                'items': self._get_sample_logs(10)
            }
            service_mock.list.return_value.execute.return_value = payload

            assert len(self._app._gather_logs()) == 10
            assert self._app._last_timestamp == '2011-06-17T15:39:18.460000Z'
            assert self._app._context['last_event_ids'] == [-12345678901234567890]

    @patch('streamalert.apps._apps.gsuite.GSuiteReportsApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_http_error(self, log_mock):
        """GSuiteReportsApp - Gather Logs, Google API HTTP Error"""
        with patch.object(self._app, '_activities_service') as service_mock:
            error = googleapiclient.errors.HttpError('response', b'bad')
            service_mock.list.return_value.execute.side_effect = error
            assert not self._app._gather_logs()
            log_mock.assert_called_with('[%s] Failed to execute activities listing', self._app)

    @patch('streamalert.apps._apps.gsuite.GSuiteReportsApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_token_error(self, log_mock):
        """GSuiteReportsApp - Gather Logs, Google API Token Error"""
        with patch.object(self._app, '_activities_service') as service_mock:
            error = exceptions.RefreshError('bad')
            service_mock.list.return_value.execute.side_effect = error
            assert not self._app._gather_logs()
            log_mock.assert_called_with('[%s] Failed to execute activities listing', self._app)

    @patch('streamalert.apps._apps.gsuite.GSuiteReportsApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_ssl_error(self, log_mock):
        """GSuiteReportsApp - Gather Logs, SSL Handshake Error"""
        with patch.object(self._app, '_activities_service') as service_mock:
            error = ssl.SSLError('_ssl.c:574: The handshake operation timed out')
            service_mock.list.return_value.execute.side_effect = error
            assert not self._app._gather_logs()
            log_mock.assert_called_with('[%s] Failed to execute activities listing', self._app)

    @patch('streamalert.apps._apps.gsuite.GSuiteReportsApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_socket_error(self, log_mock):
        """GSuiteReportsApp - Gather Logs, Socket Timeout"""
        with patch.object(self._app, '_activities_service') as service_mock:
            error = socket.timeout('timeout: timed out')
            service_mock.list.return_value.execute.side_effect = error
            assert not self._app._gather_logs()
            log_mock.assert_called_with('[%s] Failed to execute activities listing', self._app)

    @patch('streamalert.apps._apps.gsuite.GSuiteReportsApp._load_credentials',
           Mock(return_value=False))
    def test_gather_logs_no_service(self):
        """GSuiteReportsApp - Gather Logs, No Service"""
        with patch.object(self._app, '_activities_service') as service_mock:
            self._app._activities_service = False
            assert not self._app._gather_logs()
            service_mock.list.assert_not_called()

    @patch('streamalert.apps._apps.gsuite.GSuiteReportsApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.error')
    def test_gather_logs_no_results(self, log_mock):
        """GSuiteReportsApp - Gather Logs, No Results From API"""
        with patch.object(self._app, '_activities_service') as service_mock:
            service_mock.list.return_value.execute.return_value = None
            assert not self._app._gather_logs()
            log_mock.assert_called_with(
                '[%s] No results received from the G Suite API request', self._app
            )

    @patch('streamalert.apps._apps.gsuite.GSuiteReportsApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.info')
    def test_gather_logs_empty_items(self, log_mock):
        """GSuiteReportsApp - Gather Logs, Empty Activities List"""
        with patch.object(self._app, '_activities_service') as service_mock:
            payload = {
                'kind': 'reports#auditActivities',
                'nextPageToken': 'the next page\'s token',
                'items': []
            }
            service_mock.list.return_value.execute.return_value = payload
            assert not self._app._gather_logs()
            log_mock.assert_called_with(
                '[%s] No logs in response from G Suite API request', self._app
            )

    def test_gather_logs_remove_duplicate_events(self):
        """GSuiteReportsApp - Gather Logs, Remove duplicate events"""
        with patch.object(self._app, '_activities_service') as service_mock:
            payload = {
                'kind': 'reports#auditActivities',
                'nextPageToken': None,
                'items': self._get_sample_logs(10)
            }
            service_mock.list.return_value.execute.return_value = payload
            self._app._context['last_event_ids'] = [
                -12345678901234567890 + 9,
                -12345678901234567890 + 8
            ]

            assert len(self._app._gather_logs()) == 8
            assert self._app._last_timestamp == '2011-06-17T15:39:18.460000Z'
            assert self._app._more_to_poll == False
            assert self._app._context['last_event_ids'] == [-12345678901234567890]

    @staticmethod
    def _get_sample_logs(count):
        """Helper function for returning sample gsuite (admin) logs"""

        def _get_timestamp(start_timestamp, subtract_seconds):
            timestamp = datetime.strptime(start_timestamp, GSuiteReportsApp.date_formatter())
            timestamp -= timedelta(seconds=subtract_seconds)
            return timestamp.strftime(GSuiteReportsApp.date_formatter())

        return [{
            'kind': 'audit#activity',
            'id': {
                'time': _get_timestamp('2011-06-17T15:39:18.460000Z', index),
                'uniqueQualifier': -12345678901234567890 + index,
                'applicationName': 'admin',
                'customerId': 'C03az79cb'
            },
            'actor': {
                'callerType': 'USER',
                'email': 'liz@example.com',
                'profileId': 'user\'s unique G Suite profile ID',
                'key': 'consumer key of requestor in OAuth 2LO requests'
            },
            'ownerDomain': 'example.com',
            'ipAddress': 'user\'s IP address',
            'events': [
                {
                    'type': 'GROUP_SETTINGS',
                    'name': 'CHANGE_GROUP_SETTING',
                    'parameters': [
                        {
                            'name': 'SETTING_NAME',
                            'value': 'WHO_CAN_JOIN',
                            'intValue': 'integer value of parameter',
                            'boolValue': 'boolean value of parameter'
                        }
                    ]
                }
            ]
        } for index in range(count)]


@pytest.mark.xfail(raises=NotImplementedError)
def test_type_not_implemented():
    """GSuiteReportsApp - Subclass Type Not Implemented"""
    # pylint: disable=protected-access,abstract-method
    class GSuiteFakeApp(GSuiteReportsApp):
        """Fake GSuiteReports app that should raise a NotImplementedError"""

    GSuiteFakeApp._type()

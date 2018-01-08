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
import socket
import ssl

from mock import Mock, mock_open, patch

import apiclient
import oauth2client
from nose.tools import assert_equal, assert_false, assert_items_equal, assert_true, raises

from app_integrations.apps.gsuite import GSuiteReportsApp
from app_integrations.config import AppConfig

from tests.unit.app_integrations.test_helpers import (
    get_valid_config_dict,
    MockSSMClient
)

@patch.object(GSuiteReportsApp, '_type', Mock(return_value='admin'))
@patch.object(GSuiteReportsApp, 'type', Mock(return_value='type'))
@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient())
class TestGSuiteReportsApp(object):
    """Test class for the GSuiteReportsApp"""

    # Remove all abstractmethods so we can instantiate GSuiteReportsApp for testing
    @patch.object(GSuiteReportsApp, '__abstractmethods__', frozenset())
    def setup(self):
        """Setup before each method"""
        self._app = GSuiteReportsApp(AppConfig(get_valid_config_dict('gsuite_admin')))

    def test_sleep(self):
        """GSuiteReportsApp - Sleep Seconds"""
        assert_equal(self._app._sleep_seconds(), 0)

    def test_required_auth_info(self):
        """GSuiteReportsApp - Required Auth Info"""
        assert_items_equal(self._app.required_auth_info().keys(),
                           {'delegation_email', 'keyfile'})

    @patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_dict',
           Mock(return_value=True))
    def test_keyfile_validator(self):
        """GSuiteReportsApp - Keyfile Validation, Success"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        data = {'test': 'keydata'}
        mocker = mock_open(read_data=json.dumps(data))
        with patch('__builtin__.open', mocker):
            loaded_keydata = validation_function('fakepath')
            assert_equal(loaded_keydata, data)

    @patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_dict')
    def test_keyfile_validator_failure(self, cred_mock):
        """GSuiteReportsApp - Keyfile Validation, Failure"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        cred_mock.return_value = False
        mocker = mock_open(read_data=json.dumps({'test': 'keydata'}))
        with patch('__builtin__.open', mocker):
            assert_false(validation_function('fakepath'))
            cred_mock.assert_called()

    @patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_dict')
    def test_keyfile_validator_bad_json(self, cred_mock):
        """GSuiteReportsApp - Keyfile Validation, Bad JSON"""
        validation_function = self._app.required_auth_info()['keyfile']['format']
        mocker = mock_open(read_data='invalid json')
        with patch('__builtin__.open', mocker):
            assert_false(validation_function('fakepath'))
            cred_mock.assert_not_called()

    @patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_dict',
           Mock(return_value=True))
    def test_load_credentials(self):
        """GSuiteReportsApp - Load Credentials, Success"""
        assert_true(self._app._load_credentials('fakedata'))

    @patch('oauth2client.service_account.ServiceAccountCredentials.from_json_keyfile_dict')
    def test_load_credentials_bad(self, cred_mock):
        """GSuiteReportsApp - Load Credentials, ValueError"""
        cred_mock.side_effect = ValueError('Bad things happened')
        assert_false(self._app._load_credentials('fakedata'))

    @patch('app_integrations.apps.gsuite.GSuiteReportsApp._load_credentials', Mock())
    @patch('app_integrations.apps.gsuite.apiclient.discovery.build')
    def test_create_service(self, build_mock):
        """GSuiteReportsApp - Create Service, Success"""
        build_mock.return_value.activities.return_value = True
        assert_true(self._app._create_service())

    @patch('logging.Logger.debug')
    def test_create_service_exists(self, log_mock):
        """GSuiteReportsApp - Create Service, Exists"""
        self._app._activities_service = True
        assert_true(self._app._create_service())
        log_mock.assert_called_with('Service already instantiated for %s', 'type')

    @patch('app_integrations.apps.gsuite.GSuiteReportsApp._load_credentials',
           Mock(return_value=False))
    def test_create_service_fail_creds(self):
        """GSuiteReportsApp - Create Service, Credential Failure"""
        assert_false(self._app._create_service())

    @patch('app_integrations.apps.gsuite.GSuiteReportsApp._load_credentials', Mock())
    @patch('logging.Logger.exception')
    @patch('app_integrations.apps.gsuite.apiclient.discovery.build')
    def test_create_service_api_error(self, build_mock, log_mock):
        """GSuiteReportsApp - Create Service, Google API Error"""
        build_mock.side_effect = apiclient.errors.Error('This is bad')
        assert_false(self._app._create_service())
        log_mock.assert_called_with('Failed to build discovery service for %s', 'type')

    @patch('app_integrations.apps.gsuite.GSuiteReportsApp._load_credentials', Mock())
    @patch('logging.Logger.exception')
    @patch('app_integrations.apps.gsuite.apiclient.discovery.build')
    def test_create_service_ssl_error(self, build_mock, log_mock):
        """GSuiteReportsApp - Create Service, SSL Handshake Error"""
        build_mock.side_effect = ssl.SSLError('_ssl.c:574: The handshake operation timed out')
        assert_false(self._app._create_service())
        log_mock.assert_called_with('Failed to build discovery service for %s', 'type')

    @patch('app_integrations.apps.gsuite.GSuiteReportsApp._load_credentials', Mock())
    @patch('logging.Logger.exception')
    @patch('app_integrations.apps.gsuite.apiclient.discovery.build')
    def test_create_service_socket_error(self, build_mock, log_mock):
        """GSuiteReportsApp - Create Service, Socket Timeout"""
        build_mock.side_effect = socket.timeout('timeout: timed out')
        assert_false(self._app._create_service())
        log_mock.assert_called_with('Failed to build discovery service for %s', 'type')

    def test_gather_logs(self):
        """GSuiteReportsApp - Gather Logs, Success"""
        with patch.object(self._app, '_activities_service') as service_mock:
            payload = {
                'kind': 'reports#auditActivities',
                'nextPageToken': 'the next page\'s token',
                'items': self._get_sample_logs(10)
            }
            service_mock.list.return_value.execute.return_value = payload

            assert_equal(len(self._app._gather_logs()), 10)
            assert_equal(self._app._last_timestamp, '2011-06-17T15:39:18.460Z')

    @patch('app_integrations.apps.gsuite.GSuiteReportsApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_http_error(self, log_mock):
        """GSuiteReportsApp - Gather Logs, Google API HTTP Error"""
        with patch.object(self._app, '_activities_service') as service_mock:
            error = apiclient.errors.HttpError('response', bytes('bad'))
            service_mock.list.return_value.execute.side_effect = error
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('Failed to execute activities listing for %s', 'type')

    @patch('app_integrations.apps.gsuite.GSuiteReportsApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_token_error(self, log_mock):
        """GSuiteReportsApp - Gather Logs, Google API Token Error"""
        with patch.object(self._app, '_activities_service') as service_mock:
            error = oauth2client.client.HttpAccessTokenRefreshError('bad', status=502)
            service_mock.list.return_value.execute.side_effect = error
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('Failed to execute activities listing for %s', 'type')

    @patch('app_integrations.apps.gsuite.GSuiteReportsApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_ssl_error(self, log_mock):
        """GSuiteReportsApp - Gather Logs, SSL Handshake Error"""
        with patch.object(self._app, '_activities_service') as service_mock:
            error = ssl.SSLError('_ssl.c:574: The handshake operation timed out')
            service_mock.list.return_value.execute.side_effect = error
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('Failed to execute activities listing for %s', 'type')

    @patch('app_integrations.apps.gsuite.GSuiteReportsApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.exception')
    def test_gather_logs_socket_error(self, log_mock):
        """GSuiteReportsApp - Gather Logs, Socket Timeout"""
        with patch.object(self._app, '_activities_service') as service_mock:
            error = socket.timeout('timeout: timed out')
            service_mock.list.return_value.execute.side_effect = error
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('Failed to execute activities listing for %s', 'type')

    @patch('app_integrations.apps.gsuite.GSuiteReportsApp._load_credentials',
           Mock(return_value=False))
    def test_gather_logs_no_service(self):
        """GSuiteReportsApp - Gather Logs, No Service"""
        with patch.object(self._app, '_activities_service') as service_mock:
            self._app._activities_service = False
            assert_false(self._app._gather_logs())
            service_mock.list.assert_not_called()

    @patch('app_integrations.apps.gsuite.GSuiteReportsApp._create_service',
           Mock(return_value=True))
    @patch('logging.Logger.error')
    def test_gather_logs_no_results(self, log_mock):
        """GSuiteReportsApp - Gather Logs, No Results From API"""
        with patch.object(self._app, '_activities_service') as service_mock:
            service_mock.list.return_value.execute.return_value = None
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('No results received from the G Suite API request for %s',
                                        'type')

    @patch('app_integrations.apps.gsuite.GSuiteReportsApp._create_service',
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
            assert_false(self._app._gather_logs())
            log_mock.assert_called_with('No logs in response from G Suite API request for %s',
                                        'type')

    @staticmethod
    def _get_sample_logs(count):
        """Helper function for returning sample gsuite (admin) logs"""
        return [{
            'kind': 'audit#activity',
            'id': {
                'time': '2011-06-17T15:39:18.460Z',
                'uniqueQualifier': 'report\'s unique ID',
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
        } for _ in range(count)]


@raises(NotImplementedError)
def test_type_not_implemented():
    """GSuiteReportsApp - Subclass Type Not Implemented"""
    class GSuiteFakeApp(GSuiteReportsApp):
        """Fake GSuiteReports app that should raise a NotImplementedError"""

    GSuiteFakeApp._type()

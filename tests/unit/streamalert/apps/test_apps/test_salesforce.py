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

import pytest
from moto import mock_ssm
from requests.exceptions import Timeout

from streamalert.apps._apps.salesforce import SalesforceApp, SalesforceAppError
from tests.unit.streamalert.apps.test_helpers import (
    get_event, get_salesforce_log_files, list_salesforce_api_versions,
    put_mock_params)
from tests.unit.streamalert.shared.test_config import get_mock_lambda_context


@mock_ssm
@patch('time.sleep', Mock())
@patch.object(SalesforceApp, '_type', Mock(return_value='Console'))
@patch.object(SalesforceApp, 'type', Mock(return_value='type'))
class TestSalesforceApp:
    """Test class for the SalesforceApp"""
    # pylint: disable=protected-access

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup before each method"""
        # pylint: disable=attribute-defined-outside-init
        self._test_app_name = 'salesforce'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._app = SalesforceApp(self._event, self._context)

    def set_config_values(self, client_id, client_secret, username, password, security_token):
        """Helper function to setup the auth values"""
        self._app._config.auth['client_id'] = client_id
        self._app._config.auth['client_secret'] = client_secret
        self._app._config.auth['username'] = username
        self._app._config.auth['password'] = password
        self._app._config.auth['security_token'] = security_token

    @patch('requests.post')
    def test_request_token_succeeded(self, mock_post):
        """SalesforceApp - Request auth token successfully"""
        self.set_config_values(
            'CLIENT_ID', 'CLIENT_SECRET', 'USERNAME', 'PASSWORD', 'SECURITY_TOKEN'
        )

        # request post is successful but return value is None.
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value=None)
        )
        assert not self._app._request_token()

        # request post is successful and returns auth token.
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'access_token': 'AUTH_TOKEN', 'instance_url': 'MY_URL'})
        )
        assert self._app._request_token()
        assert (
            self._app._auth_headers ==
            {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer AUTH_TOKEN'
            })
        assert self._app._instance_url == 'MY_URL'

    @patch('requests.post')
    def test_request_token_failed(self, mock_post):
        """SalesforceApp - Failed to request auth token"""
        self.set_config_values(
            'CLIENT_ID', 'BAD_SECRET', 'USERNAME', 'PASSWORD', 'SECURITY_TOKEN'
        )
        # request post is failed.
        mock_post.return_value = Mock(
            status_code=403,
            json=Mock(return_value='ERROR CODE')
        )
        assert not self._app._request_token()

        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'access_token': 'ACCESS_TOKEN', 'instance_url': ''})
        )
        assert not self._app._request_token()

    def test_required_auth_info(self):
        """SalesforceApp - Required Auth Info"""
        assert collections.Counter(list(self._app.required_auth_info().keys())) == collections.Counter(
            {'client_id', 'client_secret', 'username', 'password', 'security_token'})

    @pytest.mark.xfail(raises=SalesforceAppError)
    @patch('requests.post')
    def test_validate_status_code_401(self, mock_post):
        """SalesforceApp - Validate status code 401"""
        resp = Mock(
            status_code=401,
            json=Mock(return_value={'message': 'error message', 'errorCode': 'ERROR_CODE'})
        )
        self.set_config_values(
            'CLIENT_ID', 'CLIENT_SECRET', 'USERNAME', 'PASSWORD', 'SECURITY_TOKEN'
        )
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'access_token': 'AUTH_TOKEN2', 'instance_url': 'MY_URL2'})
        )
        self._app._validate_status_code(resp)

    @patch('streamalert.apps._apps.salesforce.LOGGER.error')
    @patch('requests.post')
    def test_validate_status_code_403(self, mock_post, mock_logger):
        """SalesforceApp - Validate status code 403"""
        resp = Mock(
            status_code=403,
            json=Mock(return_value={'message': 'error message',
                                    'errorCode': 'REQUEST_LIMIT_EXCEEDED'})
        )
        self.set_config_values(
            'CLIENT_ID', 'CLIENT_SECRET', 'USERNAME', 'PASSWORD', 'SECURITY_TOKEN'
        )
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'access_token': 'AUTH_TOKEN2', 'instance_url': 'MY_URL2'})
        )
        assert not self._app._validate_status_code(resp)
        mock_logger.assert_called_with('Exceeded API request limits')

    @pytest.mark.xfail(raises=SalesforceAppError)
    @patch('requests.post')
    def test_validate_status_code_500(self, mock_post):
        """SalesforceApp - Validate status code 500"""
        resp = Mock(
            status_code=500,
            json=Mock(return_value={'message': 'error message', 'errorCode': 'ERROR_CODE'})
        )
        self.set_config_values(
            'CLIENT_ID', 'CLIENT_SECRET', 'USERNAME', 'PASSWORD', 'SECURITY_TOKEN'
        )
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'access_token': 'AUTH_TOKEN2', 'instance_url': 'MY_URL2'})
        )
        self._app._validate_status_code(resp)

    @patch('streamalert.apps._apps.salesforce.LOGGER.error')
    @patch('requests.post')
    def test_validate_status_code_204(self, mock_post, mock_logger):
        """SalesforceApp - Validate status code 204"""
        resp = Mock(
            status_code=204,
            json=Mock(return_value={'message': 'error message',
                                    'errorCode': 'ERROR_CODE'})
        )
        self.set_config_values(
            'CLIENT_ID', 'CLIENT_SECRET', 'USERNAME', 'PASSWORD', 'SECURITY_TOKEN'
        )
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'access_token': 'AUTH_TOKEN2', 'instance_url': 'MY_URL2'})
        )
        assert not self._app._validate_status_code(resp)
        mock_logger.assert_called_with(
            'Unexpected status code %d detected, error message %s',
            204, {'errorCode': 'ERROR_CODE', 'message': 'error message'})

    def test_validate_status_code_200(self):
        """SalesforceApp - Validate status code 200"""
        resp = Mock(
            status_code=200,
            json=Mock(return_value={'message': 'error message',
                                    'errorCode': 'ERROR_CODE'})
        )
        assert self._app._validate_status_code(resp)

    @patch('requests.get')
    def test_make_get_request_json(self, mock_get):
        """SalesforceApp - Make get request and return json content successfully"""
        mock_get.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'foo': 'bar'})
        )
        success, response = self._app._make_get_request('FULL_URL', {'headers': 'headers_data'})
        assert success
        assert response == {'foo': 'bar'}

    @patch('requests.get')
    def test_make_get_reques_text(self, mock_get):
        """SalesforceApp - Make get request and return raw content successfully"""
        mock_get.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=ValueError),
            text='TEXT CONTENT'
        )
        success, response = self._app._make_get_request('FULL_URL', {'headers': 'headers_data'})
        assert success
        assert response == 'TEXT CONTENT'

    @patch('streamalert.apps._apps.salesforce.LOGGER.exception')
    @patch('requests.get')
    def test_make_get_reques_timeout(self, mock_get, mock_logger):
        """SalesforceApp - Make get request and timed out"""
        mock_get.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=Timeout)
        )
        success, response = self._app._make_get_request('FULL_URL', {'headers': 'headers_data'})
        assert not success
        assert response is None
        mock_logger.assert_called_with('Request timed out for when sending get request to %s',
                                       'FULL_URL')

    @patch('requests.get')
    def test_get_latest_api_version(self, mock_get):
        """SalesforceApp - Get latest API version"""
        mock_get.return_value = Mock(
            status_code=200,
            json=Mock(return_value=list_salesforce_api_versions())
        )
        self._app._instance_url = 'my_instance_url'
        self._app._get_latest_api_version()
        assert self._app._latest_api_version == '26.0'

    @patch('streamalert.apps._apps.salesforce.LOGGER.error')
    @patch('requests.get')
    def test_get_latest_api_version_request_failed(self, mock_get, mock_logger):
        """SalesforceApp - Failed to get latest api versions"""
        mock_get.return_value = Mock(
            status_code=204,
            json=Mock(return_value={'errorCode': 'ERROR_CODE', 'message': 'error message'})
        )
        self._app._instance_url = 'my_instance_url'
        assert not self._app._get_latest_api_version()
        mock_logger.assert_called_with('Failed to fetch lastest api version')

        mock_get.return_value = Mock(
            status_code=200,
            json=Mock(return_value=[{'foo': 'bar'}])
        )
        self._app._instance_url = 'my_instance_url'
        assert not self._app._get_latest_api_version()
        mock_logger.assert_called_with('Failed to obtain latest API version')

    @patch('requests.get')
    def test_list_log_files(self, mock_get):
        """SalesforceApp - List log files"""
        mock_get.return_value = Mock(
            status_code=200,
            json=Mock(return_value=get_salesforce_log_files())
        )
        assert len(self._app._list_log_files()) == 2

    @patch('requests.get')
    def test_fetch_event_logs(self, mock_get):
        """SalesforceApp - Fetch event logs"""
        mock_get.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=ValueError),
            text='key1,key2\nvalue1a,value2a\nvalue1b,value2b'
        )
        assert (self._app._fetch_event_logs('LOG_FILE_PATH') ==
                ['value1a,value2a', 'value1b,value2b'])

    @patch('streamalert.apps._apps.salesforce.LOGGER.error')
    @patch('requests.get', Mock(side_effect=SalesforceAppError))
    def test_fetch_event_logs_exception(self, mock_logger):
        """SalesforceApp - Fetch event logs while SalesforceAppError raised"""
        assert self._app._fetch_event_logs('LOG_FILE_PATH') is None
        mock_logger.assert_called_with('Failed to get event logs', exc_info=1)

    @patch('requests.get')
    def test_fetch_event_logs_timeout(self, mock_get):
        """SalesforceApp - Fetch event logs while timeout"""
        mock_get.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=Timeout)
        )
        assert self._app._fetch_event_logs('LOG_FILE_PATH') is None

    @patch('requests.get')
    @patch('requests.post')
    def test_gather_logs(self, mock_post, mock_get):
        """SalesforceApp - Gather event logs"""
        self.set_config_values(
            'CLIENT_ID', 'CLIENT_SECRET', 'USERNAME', 'PASSWORD', 'SECURITY_TOKEN'
        )
        self._app._instance_url = 'MY_URL'

        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'access_token': 'AUTH_TOKEN', 'instance_url': 'MY_URL'})
        )

        mock_get.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=[list_salesforce_api_versions(),
                                   get_salesforce_log_files(),
                                   ValueError,
                                   ValueError]),
            text='key1,key2\nvalue1a,value2a\nvalue1b,value2b'
        )

        assert len(self._app._gather_logs()) == 4

    @patch('streamalert.apps._apps.salesforce.LOGGER.exception')
    @patch('requests.get')
    @patch('requests.post')
    def test_gather_logs_failed(self, mock_post, mock_get, mock_logger):
        """SalesforceApp - Gather event logs but log files returns empty"""
        self.set_config_values(
            'CLIENT_ID', 'CLIENT_SECRET', 'USERNAME', 'PASSWORD', 'SECURITY_TOKEN'
        )
        self._app._instance_url = 'MY_URL'

        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'access_token': 'AUTH_TOKEN', 'instance_url': 'MY_URL'})
        )

        mock_get.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=[list_salesforce_api_versions(), Timeout])
        )

        assert self._app._gather_logs() is None
        mock_logger.assert_called_once()

        mock_get.return_value = Mock(
            status_code=204,
            json=Mock(return_value={'errorCode': 'ERROR_CODE', 'message': 'error message'})
        )
        assert self._app._gather_logs() is None

    def test_sleep_seconds(self):
        """SalesforceApp - Verify sleep seconds"""
        assert self._app._sleep_seconds() == 0

    def test_date_formatter(self):
        """SalesforceApp - Verify date format"""
        assert self._app.date_formatter() == '%Y-%m-%dT%H:%M:%SZ'


@pytest.mark.xfail(raises=NotImplementedError)
def test_type_not_implemented():
    """SalesforceApp - Subclassmethod _type not implemented"""
    # pylint: disable=protected-access,abstract-method
    class SalesforceAppNoType(SalesforceApp):
        """Fake SalesforceApp that should raise a NotImplementedError"""

    SalesforceAppNoType._type()

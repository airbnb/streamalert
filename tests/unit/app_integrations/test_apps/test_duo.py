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
# pylint: disable=abstract-class-instantiated,protected-access,no-self-use,abstract-method
from mock import Mock, patch

from nose.tools import assert_equal, assert_false, assert_items_equal, raises
import requests

from app_integrations.apps.duo import DuoApp, DuoAdminApp, DuoAuthApp
from app_integrations.config import AppConfig

from tests.unit.app_integrations.test_helpers import (
    get_valid_config_dict,
    MockSSMClient
)


@patch.object(DuoApp, 'type', Mock(return_value='type'))
@patch.object(DuoApp, '_endpoint', Mock(return_value='endpoint'))
@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient())
class TestDuoApp(object):
    """Test class for the DuoApp"""

    def __init__(self):
        self._app = None

    # Remove all abstractmethods so we can instantiate DuoApp for testing
    # Also patch some abstractproperty attributes
    @patch.object(DuoApp, '__abstractmethods__', frozenset())
    def setup(self):
        """Setup before each method"""
        self._app = DuoApp(AppConfig(get_valid_config_dict('duo')))

    @patch('logging.Logger.exception')
    def test_generate_auth_hmac_failure(self, log_mock):
        """DuoApp - Generate Auth, hmac Failure"""
        self._app._config.auth['secret_key'] = {'bad_secret'}
        assert_false(self._app._generate_auth('hostname', {}))
        log_mock.assert_called_with('Could not generate hmac signature')

    def test_generate_auth(self):
        """DuoApp - Generate Auth"""
        auth = self._app._generate_auth('hostname', {})
        assert_items_equal(auth.keys(), {'Date', 'Authorization', 'Host'})

    def test_sleep(self):
        """DuoApp - Sleep Seconds"""
        self._app._poll_count = 1
        assert_equal(self._app._sleep_seconds(), 0)
        self._app._poll_count = 2
        assert_equal(self._app._sleep_seconds(), 60)

    def test_required_auth_info(self):
        """DuoApp - Required Auth Info"""
        assert_items_equal(self._app.required_auth_info().keys(),
                           {'api_hostname', 'integration_key', 'secret_key'})

    @staticmethod
    def _get_sample_logs(count, base_time):
        """Helper function for returning sample duo (auth) logs"""
        return [{
            'access_device': {},
            'device': '+1 123 456 1234',
            'factor': 'Duo Push',
            'integration': 'Test Access',
            'ip': '0.0.0.0',
            'location': {},
            'new_enrollment': False,
            'reason': 'No response',
            'result': 'FAILURE',
            'timestamp': base_time + i,
            'username': 'user.name@email.com'
        } for i in range(count)]

    @patch('requests.get')
    def test_get_duo_logs_bad_headers(self, requests_mock):
        """DuoApp - Get Duo Logs, Bad Headers"""
        self._app._config.auth['secret_key'] = {'bad_secret'}
        assert_false(self._app._get_duo_logs('hostname', 'full_url'))
        requests_mock.assert_not_called()

    @patch('requests.get')
    def test_get_duo_logs_bad_response(self, requests_mock):
        """DuoApp - Get Duo Logs, Bad Response"""
        requests_mock.return_value = Mock(
            status_code=404,
            content='something went wrong')

        assert_false(self._app._get_duo_logs('hostname', 'full_url'))

        # The .json should be called on the response once, to return the response.
        assert_equal(requests_mock.return_value.json.call_count, 1)

    @patch('requests.get')
    def test_gather_logs(self, requests_mock):
        """DuoApp - Gather Logs Entry Point"""
        log_count = 3
        base_time = 1505591612
        logs = self._get_sample_logs(log_count, base_time)

        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'response': logs})
        )

        gathered_logs = self._app._gather_logs()
        assert_equal(len(gathered_logs), log_count)
        assert_equal(self._app._last_timestamp, base_time + log_count - 1)

    @patch('requests.get')
    def test_gather_logs_empty(self, requests_mock):
        """DuoApp - Gather Logs Entry Point, Empty Response"""
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=[{'response': []}])
        )

        assert_false(self._app._gather_logs())

    @patch('requests.get')
    @patch('logging.Logger.exception')
    def test_gather_logs_bad_response(self, log_mock, requests_mock):
        """DuoApp - Gather Logs, Bad Response"""
        requests_mock.side_effect = requests.exceptions.SSLError(None, request='Bad')

        assert_false(self._app._gather_logs())
        log_mock.assert_called_with('Received bad response from duo')


@raises(NotImplementedError)
def test_endpoint_not_implemented():
    """DuoApp - Subclass Endpoint Not Implemented"""
    class DuoFakeApp(DuoApp):
        """Fake Duo app that should raise a NotImplementedError"""
        @classmethod
        def _type(cls):
            return 'fake'

    DuoFakeApp(get_valid_config_dict('duo'))._endpoint()


def test_duo_admin_endpoint():
    """DuoAdminApp - Verify Endpoint"""
    assert_equal(DuoAdminApp._endpoint(), '/admin/v1/logs/administrator')


def test_duo_admin_type():
    """DuoAdminApp - Verify Type"""
    assert_equal(DuoAdminApp._type(), 'admin')


def test_duo_auth_endpoint():
    """DuoAuthApp - Verify Endpoint"""
    assert_equal(DuoAuthApp._endpoint(), '/admin/v1/logs/authentication')


def test_duo_auth_type():
    """DuoAuthApp - Verify Type"""
    assert_equal(DuoAuthApp._type(), 'auth')

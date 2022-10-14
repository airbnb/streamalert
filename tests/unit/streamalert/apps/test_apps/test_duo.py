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
import requests
from moto import mock_ssm

from streamalert.apps._apps.duo import DuoAdminApp, DuoApp, DuoAuthApp
from tests.unit.streamalert.apps.test_helpers import get_event, put_mock_params
from tests.unit.streamalert.shared.test_config import get_mock_lambda_context


@mock_ssm
# Patching the DuoApp class-wide allows for all `test_*` methods to have
# patched `_type` and `_endpoint` methods. This _does not_ apply to the
# `setup` method, which means the `setup` method must be decorated as well.
@patch.object(DuoApp, '_type', Mock(return_value='test'))
@patch.object(DuoApp, '_endpoint', Mock(return_value='endpoint'))
# By setting the abstract methods to an empty `frozenset()`, an error requiring
# subclasses to implement the `_type` and `_endpoint`methods will not be raised.
# This also also allows us to subsequently patch these methods for use in the
# tests.
@patch.object(DuoApp, '__abstractmethods__', frozenset())
class TestDuoApp:
    """Test class for the DuoApp"""
    # pylint: disable=protected-access

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    @patch.object(DuoApp, '__abstractmethods__', frozenset())
    def setup(self):
        """Setup before each method"""
        # pylint: disable=abstract-class-instantiated,attribute-defined-outside-init
        self._test_app_name = 'duo'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._app = DuoApp(self._event, self._context)

    @patch('logging.Logger.exception')
    def test_generate_auth_hmac_failure(self, log_mock):
        """DuoApp - Generate Auth, hmac Failure"""
        self._app._config.auth['secret_key'] = {'bad_secret'}
        assert not self._app._generate_auth('hostname', {})
        log_mock.assert_called_with('Could not generate hmac signature')

    def test_generate_auth(self):
        """DuoApp - Generate Auth"""
        auth = self._app._generate_auth('hostname', {})
        assert collections.Counter(list(auth.keys())) == collections.Counter({
            'Date', 'Authorization', 'Host'})

    def test_sleep(self):
        """DuoApp - Sleep Seconds"""
        self._app._poll_count = 1
        assert self._app._sleep_seconds() == 0
        self._app._poll_count = 2
        assert self._app._sleep_seconds() == 60

    def test_required_auth_info(self):
        """DuoApp - Required Auth Info"""
        assert collections.Counter(list(self._app.required_auth_info().keys())) == collections.Counter(
            {'api_hostname', 'integration_key', 'secret_key'})

    @staticmethod
    def _get_sample_logs(count, base_time):
        """Helper function for returning sample duo (auth) logs"""
        return [{
            'access_device': {},
            'alias': '',
            'device': '+1 123 456 1234',
            'factor': 'Duo Push',
            'integration': 'Test Access',
            'ip': '0.0.0.0',  # nosec
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
        assert not self._app._get_duo_logs('hostname', 'full_url')
        requests_mock.assert_not_called()

    @patch('requests.get')
    def test_get_duo_logs_bad_response(self, requests_mock):
        """DuoApp - Get Duo Logs, Bad Response"""
        requests_mock.return_value = Mock(
            status_code=404,
            content='something went wrong')

        assert not self._app._get_duo_logs('hostname', 'full_url')

        # The .json should be called on the response once, to return the response.
        assert requests_mock.return_value.json.call_count == 1

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
        assert len(gathered_logs) == log_count
        assert self._app._last_timestamp == base_time + log_count - 1

    @patch('requests.get')
    def test_gather_logs_empty(self, requests_mock):
        """DuoApp - Gather Logs Entry Point, Empty Response"""
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(side_effect=[{'response': []}])
        )

        assert not self._app._gather_logs()

    @patch('requests.get')
    @patch('logging.Logger.exception')
    def test_gather_logs_bad_response(self, log_mock, requests_mock):
        """DuoApp - Gather Logs, Bad Response"""
        requests_mock.side_effect = requests.exceptions.SSLError(None, request='Bad')

        assert not self._app._gather_logs()
        log_mock.assert_called_with('Received bad response from duo')


@pytest.mark.xfail(raises=NotImplementedError)
def test_endpoint_not_implemented():
    """DuoApp - Subclass Endpoint Not Implemented"""
    # pylint: disable=protected-access,abstract-method
    class DuoFakeApp(DuoApp):
        """Fake Duo app that should raise a NotImplementedError"""
        @classmethod
        def _type(cls):
            return 'fake'

    DuoFakeApp._endpoint()


def test_duo_admin_endpoint():
    """DuoAdminApp - Verify Endpoint"""
    # pylint: disable=protected-access
    assert DuoAdminApp._endpoint() == '/admin/v1/logs/administrator'


def test_duo_admin_type():
    """DuoAdminApp - Verify Type"""
    # pylint: disable=protected-access
    assert DuoAdminApp._type() == 'admin'


def test_duo_auth_endpoint():
    """DuoAuthApp - Verify Endpoint"""
    # pylint: disable=protected-access
    assert DuoAuthApp._endpoint() == '/admin/v1/logs/authentication'


def test_duo_auth_type():
    """DuoAuthApp - Verify Type"""
    # pylint: disable=protected-access
    assert DuoAuthApp._type() == 'auth'

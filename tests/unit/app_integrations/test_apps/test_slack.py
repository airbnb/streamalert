"""
Copyright 2018-present, Airbnb Inc.

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
# pylint: disable=abstract-class-instantiated,protected-access,no-self-use,abstract-method,anomalous-backslash-in-string
from mock import Mock, patch
from nose.tools import assert_equal, assert_false, assert_items_equal, raises

from app_integrations.apps.slack import SlackApp, SlackAccessApp, SlackIntegrationsApp
from app_integrations.config import AppConfig


from tests.unit.app_integrations.test_helpers import (
    get_valid_config_dict,
    MockSSMClient
    )

@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient())
@patch.object(SlackApp, '_endpoint', Mock(return_value='endpoint'))
@patch.object(SlackApp, '_type', Mock(return_value='type'))
class TestSlackApp(object):
    """Test class for the SlackAccessApp"""

    def __init__(self):
        self._app = None

    @patch.object(SlackApp, '__abstractmethods__', frozenset())
    def setup(self):
        self._app = SlackApp(AppConfig(get_valid_config_dict('slack')))

    def test_required_auth_info(self):
        """SlackApp - Required Auth Info"""
        assert_items_equal(self._app.required_auth_info().keys(), {'auth_token'})

    @patch('requests.post')
    @patch('logging.Logger.exception')
    def test_error_code_return(self, log_mock, requests_mock):
        """SlackApp - Gather Logs - Bad Response"""
        requests_mock.return_value = Mock(
            status_code=404
            )
        assert_false(self._app._gather_logs())
        log_mock.assert_called_with('Received bad response from slack')

    @patch('requests.post')
    @patch('logging.Logger.exception')
    def test_error_response_from_slack(self, log_mock, requests_mock):
        """SlackApp - Gather Logs - Error Response"""
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value={'ok':False, 'error':'paid_only'})
            )
        assert_false(self._app._gather_logs())
        log_mock.assert_called_with('Received error or warning from slack')


@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient())
class TestSlackAccessApp(object):
    """Test class for the SlackAccessApp"""

    def __init__(self):
        self._app = None

    @patch.object(SlackAccessApp, '__abstractmethods__', frozenset())
    def setup(self):
        self._app = SlackAccessApp(AppConfig(get_valid_config_dict('slack')))

    def test_sleep_seconds(self):
        """SlackAccessApp - Sleep Seconds"""
        assert_equal(3, self._app._sleep_seconds())

    @staticmethod
    def _get_sample_access_logs():
        """Sample logs collected from the slack api documentation"""
        return {
            'ok': True,
            'logins': [
                {
                    'user_id': 'U12345',
                    'username': 'bob',
                    'date_first': 1422922864,
                    'date_last':  1422922864,
                    'count': 1,
                    'ip': '127.0.0.',
                    'user_agent': 'SlackWeb Mozilla\/5.0 (Macintosh; Intel Mac OS X 10_10_2) '
                                  'AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/41.0.2272.35 '
                                  'Safari\/537.36',
                    'isp': 'BigCo ISP',
                    'country': 'US',
                    'region': 'CA'
                    },
                {
                    'user_id': 'U45678',
                    'username': 'alice',
                    'date_first': 1422922493,
                    'date_last': 1422922493,
                    'count': 1,
                    'ip': '127.0.0.1',
                    'user_agent': 'SlackWeb Mozilla\/5.0 (iPhone; CPU iPhone OS 8_1_3 like Mac '
                                  'OS X) AppleWebKit\/600.1.4 (KHTML, like Gecko) Version\/8.0 '
                                  'Mobile\/12B466 Safari\/600.1.4',
                    'isp': 'BigCo ISP',
                    'country': 'US',
                    'region': 'CA'
                    },
                ],
            'paging': {
                'count': 100,
                'total': 2,
                'page': 1,
                'pages': 1
                }
            }

    @patch('requests.post')
    def test_gather_access_logs(self, requests_mock):
        """SlackAccessApp - Gather Logs Entry Point"""
        logs = self._get_sample_access_logs()
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
            )

        gathered_logs = self._app._gather_logs()
        assert_equal(len(gathered_logs), 2)

    @patch('requests.post')
    def test_gather_access_logs_some_filtered(self, requests_mock):
        """SlackAccessApp - Gather Logs - Some Filtered"""
        logs = self._get_sample_access_logs()
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
            )

        self._app._last_timestamp = 1422922593
        gathered_logs = self._app._gather_logs()
        assert_equal(len(gathered_logs), 1)

    @patch('requests.post')
    def test_gather_access_logs_all_filtered(self, requests_mock):
        """SlackAccessApp - Gather Logs - All Filtered"""
        logs = self._get_sample_access_logs()
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
            )

        self._app._last_timestamp = 1522922593
        gathered_logs = self._app._gather_logs()
        assert_equal(len(gathered_logs), 0)

    @patch('requests.post')
    def test_gather_logs_no_entries(self, requests_mock):
        """SlackAccessApp - Gather Logs - No Entries Returned"""
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value={
                'ok':True,
                'logins':[], 'paging':{'count':100, 'total':0, 'page':1, 'pages':1}})
            )
        assert_equal(0, len(self._app._gather_logs()))

    @patch('requests.post')
    def test_gather_logs_malformed_response(self, requests_mock):
        """SlackAccessApp - Gather Logs - Malformed Response"""
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value={
                'ok':True,
                'paging':{'count':100, 'total':0, 'page':1, 'pages':1}})
            )
        assert_false(self._app._gather_logs())

    @patch('requests.post')
    def test_gather_logs_basic_pagination(self, requests_mock):
        """SlackAccessApp - Gather Logs - Basic Pagination Handling"""
        logs = self._get_sample_access_logs()
        logs['paging']['pages'] = logs['paging']['pages'] + 1
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
            )

        self._app._last_timestamp = 1522922593
        gathered_logs = self._app._gather_logs()
        assert_equal(len(gathered_logs), 0)
        assert_equal(self._app._next_page, 2)
        assert_equal(True, self._app._more_to_poll)

    @patch('requests.post')
    def test_gather_logs_before_parameter(self, requests_mock):
        """SlackAccessApp - Gather Logs - Pagination With Before Parameter"""
        logs = self._get_sample_access_logs()
        self._app._SLACK_API_MAX_PAGE_COUNT = 1
        self._app._SLACK_API_MAX_ENTRY_COUNT = 100
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
            )

        self._app._last_timestamp = 1522922593
        gathered_logs = self._app._gather_logs()
        assert 'before' not in requests_mock.call_args[1]['data'].keys()
        assert_equal(len(gathered_logs), 0)
        assert_equal(self._app._next_page, 1)
        assert_equal(True, self._app._more_to_poll)
        assert_equal(self._app._before_time, logs['logins'][-1]['date_first'])

        self._app._gather_logs()
        assert 'before' in requests_mock.call_args[1]['data'].keys()


@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient())
class TestSlackIntegrationsApp(object):
    """Test class for the SlackIntegrationsApp"""

    def __init__(self):
        self._app = None

    @patch.object(SlackIntegrationsApp, '__abstractmethods__', frozenset())
    def setup(self):
        self._app = SlackIntegrationsApp(AppConfig(get_valid_config_dict('slack')))

    def test_sleep_seconds(self):
        """SlackIntegrationsApp - Sleep Seconds"""
        assert_equal(3, self._app._sleep_seconds())

    @patch('requests.post')
    def test_gather_logs_malformed_response(self, requests_mock):
        """SlackIntegrationsApp - Gather Logs - Malformed Response"""
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value={
                'ok':True,
                'paging':{'count':100, 'total':0, 'page':1, 'pages':1}})
            )
        assert_false(self._app._gather_logs())

    @staticmethod
    def _get_sample_integrations_logs():
        """Sample logs collected from the slack api documentation"""
        return {
            'ok': True,
            'logs': [
                {
                    'service_id': '1234567890',
                    'service_type': 'Google Calendar',
                    'user_id': 'U1234ABCD',
                    'user_name': 'Johnny',
                    'channel': 'C1234567890',
                    'date': '1392163200',
                    'change_type': 'enabled',
                    'scope': 'incoming-webhook'
                    },
                {
                    'app_id': '2345678901',
                    'app_type': 'Johnny App',
                    'user_id': 'U2345BCDE',
                    'user_name': 'Billy',
                    'date': '1392163201',
                    'change_type': 'added',
                    'scope': 'chat:write:user,channels:read'
                    },
                {
                    'service_id': '3456789012',
                    'service_type': 'Airbrake',
                    'user_id': 'U3456CDEF',
                    'user_name': 'Joey',
                    'channel': 'C1234567890',
                    'date': '1392163202',
                    'change_type': 'disabled',
                    'reason': 'user',
                    'scope': 'incoming-webhook'
                    }
                ],
            'paging': {
                'count': 3,
                'total': 3,
                'page': 1,
                'pages': 1
                }
            }

    @patch('requests.post')
    def test_gather_integrations_logs(self, requests_mock):
        """SlackIntegrationsApp - Gather Logs Entry Point"""
        logs = self._get_sample_integrations_logs()
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
            )

        gathered_logs = self._app._gather_logs()
        assert_equal(len(gathered_logs), 3)

    @patch('requests.post')
    def test_gather_integration_logs_filtered(self, requests_mock):
        """SlackIntegrationsApp - Gather Logs - Some Filtered"""
        logs = self._get_sample_integrations_logs()
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
            )

        self._app._last_timestamp = 1392163201
        gathered_logs = self._app._gather_logs()
        assert_equal(len(gathered_logs), 1)

    @patch('requests.post')
    def test_gather_logs_basic_pagination(self, requests_mock):
        """SlackIntegrationsApp - Gather Logs - Basic Pagination Handling"""
        logs = self._get_sample_integrations_logs()
        logs['paging']['pages'] = logs['paging']['pages'] + 1
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
            )

        self._app._last_timestamp = 1392163204
        gathered_logs = self._app._gather_logs()
        assert_equal(len(gathered_logs), 0)
        assert_equal(self._app._next_page, 2)
        assert_equal(True, self._app._more_to_poll)

@raises(NotImplementedError)
def test_type_not_implemented():
    """SlackApp - Subclass Type Not Implemented"""
    class SlackFakeApp(SlackApp):
        """Fake Slack app that should raise a NotImplementedError"""
        @classmethod
        def _endpoint(cls):
            return 'fake'

        @classmethod
        def _sleep_seconds(cls):
            return 0

    SlackFakeApp(get_valid_config_dict('slack'))._type()

@raises(NotImplementedError)
def test_sleep_not_implemented():
    """SlackApp - Subclass Sleep Seconds Not Implemented"""
    class SlackFakeApp(SlackApp):
        """Fake Slack app that should raise a NotImplementedError"""
        @classmethod
        def _type(cls):
            return 'fake'

        @classmethod
        def _endpoint(cls):
            return 0

    SlackFakeApp(get_valid_config_dict('slack'))._sleep_seconds()

@raises(NotImplementedError)
def test_endpoint_not_implemented():
    """SlackApp - Subclass Endpoint Not Implemented"""
    class SlackFakeApp(SlackApp):
        """Fake Slack app that should raise a NotImplementedError"""
        @classmethod
        def _type(cls):
            return 'fake'

        @classmethod
        def _sleep_seconds(cls):
            return 0

    SlackFakeApp(get_valid_config_dict('slack'))._endpoint()

@raises(NotImplementedError)
def test_filter_entries_not_implemented():
    """SlackApp - Subclass Filter Entries Not Implemented"""
    class SlackFakeApp(SlackApp):
        """Fake Slack app that should raise a NotImplementedError"""
        @classmethod
        def _type(cls):
            return 'fake'

        @classmethod
        def _endpoint(cls):
            return 0

    SlackFakeApp(get_valid_config_dict('slack'))._filter_response_entries("")

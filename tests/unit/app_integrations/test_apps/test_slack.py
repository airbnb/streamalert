from mock import Mock, patch
from nose.tools import assert_equal, assert_false, assert_items_equal, raises
import requests

from app_integrations.apps.slack import SlackApp, SlackAccessApp, SlackIntegrationsApp
from app_integrations.config import AppConfig


from tests.unit.app_integrations.test_helpers import (
        get_valid_config_dict,
        MockSSMClient
        )

@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient())
class TestSlackAccessApp(object):
    """Test class for the SlackApp"""

    def __init__(self):
        self._app = None

    @patch.object(SlackAccessApp, '__abstractmethods__', frozenset())
    def setup(self):
        self._app = SlackAccessApp(AppConfig(get_valid_config_dict('slack')))

    def test_required_auth_info(self):
        """SlackApp - Required Auth Info"""
        assert_items_equal(self._app.required_auth_info().keys(), {'auth_token'})

    @staticmethod
    def _get_sample_access_logs():
        return {
            u"ok": True,
            u"logins": [
                {
                    u"user_id": u"U12345",
                    u"username": u"bob",
                    u"date_first": 1422922864,
                    u"date_last":  1422922864,
                    u"count": 1,
                    u"ip": u"127.0.0.1",
                    u"user_agent": u"SlackWeb Mozilla\/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit\/537.36 (KHTML, like Gecko) Chrome\/41.0.2272.35 Safari\/537.36",
                    u"isp": u"BigCo ISP",
                    u"country": u"US",
                    u"region": u"CA"
                    },
                {
                    u"user_id": u"U45678",
                    u"username": u"alice",
                    u"date_first": 1422922493,
                    u"date_last": 1422922493,
                    u"count": 1,
                    u"ip": u"127.0.0.1",
                    u"user_agent": u"SlackWeb Mozilla\/5.0 (iPhone; CPU iPhone OS 8_1_3 like Mac OS X) AppleWebKit\/600.1.4 (KHTML, like Gecko) Version\/8.0 Mobile\/12B466 Safari\/600.1.4",
                    u"isp": u"BigCo ISP",
                    u"country": u"US",
                    u"region": u"CA"
                    },
                ],
            u"paging": {
                u"count": 100,
                u"total": 2,
                u"page": 1,
                u"pages": 1
                }
            }

    @patch('requests.post')
    def test_gather_access_logs(self, requests_mock):
        """SlackApp - Gather Logs Entry Point"""
        logs = self._get_sample_access_logs()
        requests_mock.return_value = Mock(
                status_code=200,
                json=Mock(return_value=logs)
                )

        gathered_logs = self._app._gather_logs()
        assert_equal(len(gathered_logs), 2)

    @patch('requests.post')
    def test_gather_access_logs_filtered(self, requests_mock):
        """SlackApp - Gather Logs And Filter Old Entries"""
        logs = self._get_sample_access_logs()
        requests_mock.return_value = Mock(
                status_code=200,
                json=Mock(return_value=logs)
                )

        self._app._last_timestamp = 1422922593
        gathered_logs = self._app._gather_logs()
        assert_equal(len(gathered_logs), 1)


@patch.object(AppConfig, 'SSM_CLIENT', MockSSMClient())
class TestSlackIntegrationsApp(object):
    """Test class for the SlackApp"""

    def __init__(self):
        self._app = None

    @patch.object(SlackIntegrationsApp, '__abstractmethods__', frozenset())
    def setup(self):
        self._app = SlackIntegrationsApp(AppConfig(get_valid_config_dict('slack')))

    def test_required_auth_info(self):
        """SlackApp - Required Auth Info"""
        assert_items_equal(self._app.required_auth_info().keys(), {'auth_token'})

    @staticmethod
    def _get_sample_integrations_logs():
        return {
            u"ok": True,
            u"logs": [
                {
                    u"service_id": u"1234567890",
                    u"service_type": u"Google Calendar",
                    u"user_id": u"U1234ABCD",
                    u"user_name": u"Johnny",
                    u"channel": u"C1234567890",
                    u"date": u"1392163200",
                    u"change_type": u"enabled",
                    u"scope": u"incoming-webhook"
                    },
                {
                    u"app_id": u"2345678901",
                    u"app_type": u"Johnny App",
                    u"user_id": u"U2345BCDE",
                    u"user_name": u"Billy",
                    u"date": u"1392163201",
                    u"change_type": u"added",
                    u"scope": u"chat:write:user,channels:read"
                    },
                {
                    u"service_id": u"3456789012",
                    u"service_type": u"Airbrake",
                    u"user_id": u"U3456CDEF",
                    u"user_name": u"Joey",
                    u"channel": u"C1234567890",
                    u"date": u"1392163202",
                    u"change_type": u"disabled",
                    u"reason": u"user",
                    u"scope": u"incoming-webhook"
                    }
                ],
            u"paging": {
                u"count": 3,
                u"total": 3,
                u"page": 1,
                u"pages": 1
                }
            }

    @patch('requests.post')
    def test_gather_integrations_logs(self, requests_mock):
        """SlackApp - Gather Logs Entry Point"""
        logs = self._get_sample_integrations_logs()
        requests_mock.return_value = Mock(
                status_code=200,
                json=Mock(return_value=logs)
                )

        gathered_logs = self._app._gather_logs()
        assert_equal(len(gathered_logs), 3)


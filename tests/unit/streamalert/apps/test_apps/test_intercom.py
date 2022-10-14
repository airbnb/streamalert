import collections
import os
from unittest.mock import Mock, patch

from moto import mock_ssm

from streamalert.apps._apps.intercom import IntercomApp
from tests.unit.streamalert.apps.test_helpers import get_event, put_mock_params
from tests.unit.streamalert.shared.test_config import get_mock_lambda_context

# import requests


@mock_ssm
class TestIntercomApp:
    """Test class for the IntercomApp"""
    # pylint: disable=protected-access

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup before each method"""
        # pylint: disable=abstract-class-instantiated,attribute-defined-outside-init
        self._test_app_name = 'intercom'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name)
        self._app = IntercomApp(self._event, self._context)
        self._app._config.auth['token'] = 'good_token'  # nosec

    def test_required_auth_info(self):
        """IntercomApp - Required Auth Info"""
        assert collections.Counter(
            self._app._required_auth_info().keys()) == collections.Counter(
            {'token'})

    @staticmethod
    def _get_sample_access_logs():
        """Sample logs"""
        return {
            'type': 'activity_log.list',
            'pages': {
                'type': 'pages',
                'next': None,
                'page': 1,
                'per_page': 20,
                'total_pages': 1
            },
            'activity_logs': [
                {
                    'id': '1234',
                    'performed_by': {
                        'type': 'admin',
                        'id': '4321',
                        'email': 'cool.admin@company.com',
                        'ip': '10.27.91.27'
                    },
                    'metadata': {
                        'sign_in_method': 'email'
                    },
                    'created_at': '1537130098',
                    'activity_type': 'admin_login_success',
                    'activity_description': 'Cool Admin successfully logged in.'
                },
                {
                    'id': '1235',
                    'performed_by': {
                        'type': 'admin',
                        'id': '5321',
                        'email': 'also.cool.admin@company.com',
                        'ip': '79.120.152.79'
                    },
                    'metadata': {
                        'message': {
                            'id': '5678',
                            'title': 'All things cool'
                        },
                        'before': 'draft',
                        'after': 'live'
                    },
                    'created_at': '1537218403',
                    'activity_type': 'message_state_change',
                    'activity_description':
                    'Also Cool Admin changed your All things cool message from draft to live.'
                },
            ]
        }

    def test_headers(self):
        return {
            'Authorization': f"Bearer {self._app._config.auth['token']}",
            'Accept': 'application/json'}

    @patch('requests.get')
    def test_gather_intercom_logs_bad_response(self, requests_mock):
        """IntercomApp - Gather Logs, Bad Response"""
        requests_mock.return_value = Mock(
            status_code=404,
            content='something went wrong')

        assert not self._app._gather_logs()

        # The .json should be called on the response once, to return the response.
        assert requests_mock.return_value.json.call_count == 1

    @patch('calendar.timegm')
    @patch('requests.get')
    def test_gather_intercom_logs_no_pagination(self, requests_mock, time_mock):
        """IntercomApp - Gather Logs No Pagination"""
        logs = self._get_sample_access_logs()
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
        )

        time_mock.return_value = 100

        gathered_logs = self._app._gather_logs()

        params = {
            'created_at_before': 100,
            'created_at_after': 0
        }

        assert len(gathered_logs) == 2
        assert not self._app._more_to_poll
        assert self._app._next_page is None
        requests_mock.assert_called_once_with(
            self._app._INTERCOM_LOGS_URL,
            headers=self.test_headers(),
            params=params,
            timeout=self._app._DEFAULT_REQUEST_TIMEOUT)

    @patch('calendar.timegm')
    @patch('requests.get')
    def test_gather_intercom_logs_response_with_next_page(self, requests_mock, time_mock):
        """IntercomApp - Gather Logs Next Page"""
        logs = self._get_sample_access_logs()
        logs['pages']['next'] = '1234abc'
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
        )

        time_mock.return_value = 100

        gathered_logs = self._app._gather_logs()

        params = {
            'created_at_before': 100,
            'created_at_after': 0
        }

        assert len(gathered_logs) == 2
        assert self._app._more_to_poll
        assert self._app._next_page == '1234abc'
        requests_mock.assert_called_once_with(
            self._app._INTERCOM_LOGS_URL,
            headers=self.test_headers(),
            params=params,
            timeout=self._app._DEFAULT_REQUEST_TIMEOUT)

    @patch('requests.get')
    def test_gather_intercom_logs_pagination(self, requests_mock):
        """IntercomApp - Gather Logs Pagination"""
        logs = self._get_sample_access_logs()
        self._app._next_page = '567cde'
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
        )

        gathered_logs = self._app._gather_logs()

        assert len(gathered_logs) == 2
        requests_mock.assert_called_once_with(
            '567cde',
            headers=self.test_headers(),
            params=None,
            timeout=self._app._DEFAULT_REQUEST_TIMEOUT)

    @patch('calendar.timegm')
    @patch('requests.get')
    def test_gather_intercom_logs_setting_last_timestamp(self, requests_mock, time_mock):
        """IntercomApp - Gather Logs Setting _last_timestamp"""
        logs = self._get_sample_access_logs()
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
        )

        time_mock.return_value = 100
        assert self._app._last_timestamp == 0

        gathered_logs = self._app._gather_logs()

        params = {
            'created_at_before': 100,
            'created_at_after': 0
        }

        assert len(gathered_logs) == 2
        assert self._app._last_timestamp == 1537218403
        requests_mock.assert_called_once_with(
            self._app._INTERCOM_LOGS_URL,
            headers=self.test_headers(),
            params=params,
            timeout=self._app._DEFAULT_REQUEST_TIMEOUT)

    @patch('calendar.timegm')
    @patch('requests.get')
    def test_gather_intercom_logs_by_last_timestamp(self, requests_mock, time_mock):
        """IntercomApp - Gather Logs Filtering By _last_timestamp"""
        logs = self._get_sample_access_logs()
        self._app._last_timestamp = 1537218402
        requests_mock.return_value = Mock(
            status_code=200,
            json=Mock(return_value=logs)
        )

        time_mock.return_value = 100

        gathered_logs = self._app._gather_logs()

        params = {
            'created_at_before': 100,
            'created_at_after': 1537218402
        }

        assert len(gathered_logs) == 1
        assert self._app._last_timestamp == 1537218403
        requests_mock.assert_called_once_with(
            self._app._INTERCOM_LOGS_URL,
            headers=self.test_headers(),
            params=params,
            timeout=self._app._DEFAULT_REQUEST_TIMEOUT)

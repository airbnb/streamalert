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
from mock import patch
from nose.tools import assert_equal, assert_false, assert_items_equal

from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException

from app_integrations.apps.aliyun import AliyunApp
from app_integrations.config import AppConfig

from tests.unit.app_integrations.test_helpers import (
    get_valid_config_dict
    )


class TestAliyunApp(object):
    """Test class for the AliyunApp"""

    def __init__(self):
        self._app = None

    @patch.object(AliyunApp, '__abstractmethods__', frozenset())
    def setup(self):
        self._app = AliyunApp(AppConfig(get_valid_config_dict('aliyun')))

    def test_sleep_seconds(self):
        """AliyunApp - Sleep Seconds"""
        assert_equal(0, self._app._sleep_seconds())

    def test_date_formatter(self):
        """AliyunApp - Date Formatter"""
        assert_equal(self._app.date_formatter(), '%Y-%m-%dT%H:%M:%SZ')

    def test_required_auth_into(self):
        """AliyunApp - Required Auth Info"""
        assert_items_equal(self._app.required_auth_info().keys(),
                           {'access_key_id', 'access_key_secret', 'region_id'})

    def test_region_validator_success(self):
        """AliyunApp - Region Validation, Success"""
        validation_function = self._app.required_auth_info()['region_id']['format']
        assert_equal(validation_function('ap-northeast-1'), 'ap-northeast-1')

    def test_region_validator_failure(self):
        """AliyunApp - Region Validation, Failure"""
        validation_function = self._app.required_auth_info()['region_id']['format']
        assert_equal(validation_function('ap-northeast'), False)

    @patch('aliyunsdkcore.client.AcsClient.do_action_with_exception')
    @patch('logging.Logger.exception')
    def test_server_exception(self, log_mock, client_mock):
        """AliyunApp - Server Exception"""
        client_mock.side_effect = ServerException("error", "bad server response")
        assert_false(self._app._gather_logs())
        log_mock.assert_called_with("Server Exception: %s",
                                    "HTTP Status: None Error:error bad server "
                                    "response RequestID: None")

    @patch('aliyunsdkcore.client.AcsClient.do_action_with_exception')
    @patch('logging.Logger.exception')
    def test_client_exception(self, log_mock, client_mock):
        """AliyunApp - Client Exception"""
        client_mock.side_effect = ClientException("error", "bad client")
        assert_false(self._app._gather_logs())
        log_mock.assert_called_with("Client Exception: %s", "error bad client")

    @patch('aliyunsdkcore.client.AcsClient.do_action_with_exception')
    def test_gather_logs_no_more_entries(self, client_mock):
        """AliyunApp - Gather Logs with no entries"""
        client_mock.return_value = '{"RequestId":"B1DE97F8-5450-4593-AB38-FB61B799E91D",' \
                                   '"Events":[],"EndTime":"2018-07-23T19:28:00Z",' \
                                   '"StartTime":"2018-06-23T19:28:30Z"}'
        self._app._next_token = "20"
        logs = self._app._gather_logs()
        args, _ = client_mock.call_args
        assert_equal(args[0].get_NextToken(), "20")
        assert_equal(0, len(logs))
        assert_false(self._app._more_to_poll)
        assert_equal("2018-07-23T19:28:00Z", self._app._last_timestamp)

    @patch('aliyunsdkcore.client.AcsClient.do_action_with_exception')
    def test_gather_logs_entries(self, client_mock):
        """AliyunApp - Gather Logs with some entries"""
        client_mock.return_value = '{"NextToken":"20","RequestId":'\
                                   '"B1DE97F8-5450-4593-AB38-FB61B799E91D",' \
                                   '"Events":["filler data","filler data"],' \
                                   '"EndTime":"2018-07-23T19:28:00Z",' \
                                   '"StartTime":"2018-06-23T19:28:30Z"}'
        logs = self._app._gather_logs()
        assert_equal(2, len(logs))
        assert self._app._more_to_poll
        assert_equal(self._app._next_token, "20")

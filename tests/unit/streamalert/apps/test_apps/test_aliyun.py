"""
Copyright 2018-present Airbnb, Inc.

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
from unittest.mock import patch

import pytest
from aliyunsdkcore.acs_exception.exceptions import ServerException
from moto import mock_ssm

from streamalert.apps._apps.aliyun import AliyunApp
from tests.unit.streamalert.apps.test_helpers import get_event, put_mock_params
from tests.unit.streamalert.shared.test_config import get_mock_lambda_context


@mock_ssm
class TestAliyunApp:
    """Test class for the AliyunApp"""
    # pylint: disable=protected-access

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup before each method"""
        # pylint: disable=attribute-defined-outside-init
        self._test_app_name = 'aliyun'
        put_mock_params(self._test_app_name)
        self._event = get_event(self._test_app_name)
        self._context = get_mock_lambda_context(self._test_app_name, milliseconds=100000)
        self._app = AliyunApp(self._event, self._context)

    def test_sleep_seconds(self):
        """AliyunApp - Sleep Seconds"""
        assert 0 == self._app._sleep_seconds()

    def test_date_formatter(self):
        """AliyunApp - Date Formatter"""
        assert self._app.date_formatter() == '%Y-%m-%dT%H:%M:%SZ'

    def test_required_auth_info(self):
        """AliyunApp - Required Auth Info"""
        assert collections.Counter(list(self._app.required_auth_info().keys())) == collections.Counter(
            {'access_key_id', 'access_key_secret', 'region_id'})

    def test_region_validator_success(self):
        """AliyunApp - Region Validation, Success"""
        validation_function = self._app.required_auth_info()['region_id']['format']
        assert validation_function('ap-northeast-1') == 'ap-northeast-1'

    def test_region_validator_failure(self):
        """AliyunApp - Region Validation, Failure"""
        validation_function = self._app.required_auth_info()['region_id']['format']
        assert validation_function('ap-northeast') == False

    @pytest.mark.xfail(raises=ServerException)
    @patch('aliyunsdkcore.client.AcsClient.do_action_with_exception')
    @patch('logging.Logger.exception')
    def test_server_exception(self, log_mock, client_mock):
        """AliyunApp - Gather Logs, Exception"""
        client_mock.side_effect = ServerException("error", "bad server response")
        self._app._gather_logs()
        log_mock.assert_called_with("%s error occurred", "Server")

    def test_gather_logs_last_timestamp_set(self):
        """AliyunApp - Request Creation"""
        assert self._app.request.get_StartTime() == '2018-07-23T15:42:11Z'
        assert self._app.request.get_MaxResults() == AliyunApp._MAX_RESULTS

    @patch('aliyunsdkcore.client.AcsClient.do_action_with_exception')
    def test_gather_logs_no_more_entries(self, client_mock):
        """AliyunApp - Gather Logs with no entries"""
        client_mock.return_value = '{"RequestId":"B1DE97F8-5450-4593-AB38-FB61B799E91D",' \
                                   '"Events":[],"EndTime":"2018-07-23T19:28:00Z",' \
                                   '"StartTime":"2018-06-23T19:28:30Z"}'
        logs = self._app._gather_logs()
        assert 0 == len(logs)
        assert not self._app._more_to_poll
        assert "2018-07-23T19:28:00Z" == self._app._last_timestamp

    @patch('aliyunsdkcore.client.AcsClient.do_action_with_exception')
    def test_gather_logs_entries(self, client_mock):
        """AliyunApp - Gather Logs with some entries"""
        client_mock.return_value = '{"NextToken":"20","RequestId":'\
                                   '"B1DE97F8-5450-4593-AB38-FB61B799E91D",' \
                                   '"Events":[{"eventTime":"123"},{"eventTime":"123"}],' \
                                   '"EndTime":"2018-07-23T19:28:00Z",' \
                                   '"StartTime":"2018-06-23T19:28:30Z"}'
        logs = self._app._gather_logs()
        assert 2 == len(logs)
        assert self._app._more_to_poll
        assert self._app.request.get_NextToken() == "20"

    @patch('streamalert.apps.app_base.AppIntegration._invoke_successive_app')
    @patch('streamalert.apps.batcher.Batcher._send_logs_to_lambda')
    @patch('streamalert.apps._apps.aliyun.AliyunApp._sleep_seconds')
    @patch('aliyunsdkcore.client.AcsClient.do_action_with_exception')
    def test_gather_logs_last_timestamp(self, client_mock, sleep_mock, batcher_mock, _):
        """AliyunApp - Test last_timestamp"""
        # mock 3 responses
        mock_resps = [
            {
                'NextToken': '50',
                'RequestId': 'AAAAAAAA',
                'Events': [
                    {
                        'eventTime': '2018-06-23T19:29:00Z'
                    },
                    {
                        'eventTime': '2018-06-23T19:28:00Z'
                    }
                ],
                'EndTime': '2018-07-23T19:28:00Z',
                'StartTime': '2018-06-23T19:28:30Z'
            },
            {
                'NextToken': '100',
                'RequestId': 'BBBBBBBBB',
                'Events': [
                    {
                        'eventTime': '2018-06-24T19:29:00Z'
                    },
                    {
                        'eventTime': '2018-06-24T19:28:00Z'
                    }
                ],
                'EndTime': '2018-07-23T19:28:00Z',
                'StartTime': '2018-06-23T19:28:30Z'
            },
            {
                'NextToken': '150',
                'RequestId': 'CCCCCCCC',
                'Events': [
                    {
                        'eventTime': '2018-06-25T19:29:00Z'
                    },
                    {
                        'eventTime': '2018-06-25T19:28:00Z'
                    }
                ],
                'EndTime': '2018-07-23T19:28:00Z',
                'StartTime': '2018-06-23T19:28:30Z'
            }
        ]
        client_mock.side_effect = [json.dumps(r, separators=(',', ':')) for r in mock_resps]

        # Mock remaining time. _sleep_seconds() methods will be called twice when
        # make a call to gather logs via Aliyun API. Set sleep second to a large number
        # to mimic corner case that there are still more logs to pull while lambda function
        # timeout is reached. In this case, the _last_timestamp stamp should be updated
        # correctly.
        sleep_mock.side_effect = [0, 0, 0, 0, 1000000, 0]

        # Mock 3 batcher call to invoke successive lambda function since there are more logs
        batcher_mock.side_effect = [True, True, True]

        self._app.gather()
        assert self._app._poll_count == 3
        assert self._app._more_to_poll
        assert self._app.request.get_NextToken() == "150"
        assert self._app._last_timestamp == '2018-07-23T19:28:00Z'

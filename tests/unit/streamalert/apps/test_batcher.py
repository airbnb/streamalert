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
import os
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from streamalert.apps.batcher import Batcher
from tests.unit.streamalert.apps.test_helpers import MockLambdaClient


class TestAppBatcher:
    """Class for handling testing of the app integration output batcher"""
    # pylint: disable=protected-access

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Setup class before tests"""
        # pylint: disable=attribute-defined-outside-init
        self.batcher = Batcher('duo_auth', 'destination_func')

        # Use a mocked version of the Lambda client to patch out the instance client
        Batcher.LAMBDA_CLIENT = MockLambdaClient

    @patch('logging.Logger.info')
    def test_send_logs_lambda_success(self, log_mock):
        """App Integration Batcher - Send Logs to StreamAlert, Successful"""
        log_count = 5
        logs = [{'timestamp': 'time',
                 'eventtype': 'authentication',
                 'host': 'host'} for _ in range(log_count)]

        result = self.batcher._send_logs_to_lambda(logs)

        assert result
        log_mock.assert_called_with('Sent %d logs to \'%s\' with Lambda request ID \'%s\'',
                                    log_count, 'destination_func',
                                    '9af88643-7b3c-43cd-baae-addb73bb4d27')

    @pytest.mark.xfail(raises=ClientError)
    def test_send_logs_lambda_exception(self):
        """App Integration Batcher - Send Logs to StreamAlert, Exception"""
        MockLambdaClient._raise_exception = True
        logs = [{'timestamp': 'time',
                 'eventtype': 'authentication',
                 'host': 'host'}]

        self.batcher._send_logs_to_lambda(logs)

    def test_send_logs_lambda_too_large(self):
        """App Integration Batcher - Send Logs to StreamAlert, Exceeds Size"""
        # The length of the below list of logs dumped to json should exceed the
        # max AWS lambda input size of 128000 (this results in 128001)
        logs = [{'timestamp': 'time',
                 'eventtype': 'authentication',
                 'host': 'host'} for _ in range(2000)]
        result = self.batcher._send_logs_to_lambda(logs)

        assert not result

    @patch('logging.Logger.error')
    def test_segment_and_send_one_over_max(self, log_mock):
        """App Integration Batcher - Drop One Log Over Max Size"""
        logs = [{'random_data': 'a' * 128000}]
        assert self.batcher._send_logs_to_lambda(logs)

        log_mock.assert_called_with('Log payload size for single log exceeds input '
                                    'limit and will be dropped (%d > %d max).',
                                    128072, 128000)

    @patch('streamalert.apps.batcher.Batcher._send_logs_to_lambda')
    def test_segment_and_send(self, batcher_mock):
        """App Integration Batcher - Segment and Send Logs to StreamAlert"""
        logs = [{'timestamp': 'time',
                 'eventtype': 'authentication',
                 'host': 'host'} for _ in range(3000)]
        self.batcher._segment_and_send(logs)

        assert batcher_mock.call_count == 2

    @patch('streamalert.apps.batcher.Batcher._send_logs_to_lambda')
    def test_segment_and_send_multi(self, batcher_mock):
        """App Integration Batcher - Segment and Send Logs to StreamAlert, Multi-segment"""
        batcher_mock.side_effect = [False, True, True, True]
        logs = [{'timestamp': 'time',
                 'eventtype': 'authentication',
                 'host': 'host'} for _ in range(6000)]
        self.batcher._segment_and_send(logs)

        assert batcher_mock.call_count == 4

    @patch('streamalert.apps.batcher.Batcher._segment_and_send')
    def test_send_logs_one_batch(self, batcher_mock):
        """App Integration Batcher - Send Logs, One batch"""
        logs = [{'timestamp': 'time',
                 'eventtype': 'authentication',
                 'host': 'host'} for _ in range(1000)]
        self.batcher.send_logs(logs)

        batcher_mock.assert_not_called()

    @patch('streamalert.apps.batcher.Batcher._segment_and_send')
    def test_send_logs_multi_batch(self, batcher_mock):
        """App Integration Batcher - Send Logs, Multi-batch"""
        logs = [{'timestamp': 'time',
                 'eventtype': 'authentication',
                 'host': 'host'} for _ in range(3000)]
        self.batcher.send_logs(logs)

        batcher_mock.assert_called()

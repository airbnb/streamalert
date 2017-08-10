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
from datetime import datetime

from botocore.exceptions import ClientError
from mock import patch
from nose.tools import assert_equal

from stream_alert.rule_processor.config import load_env
from stream_alert.rule_processor.sink import StreamSink
from tests.unit.stream_alert_rule_processor.test_helpers import get_mock_context


class TestStreamSink(object):
    """Test class for StreamSink"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        patcher = patch('stream_alert.rule_processor.sink.boto3.client')
        cls.boto_mock = patcher.start()
        context = get_mock_context()
        env = load_env(context)
        cls.sinker = StreamSink(env)

    @classmethod
    def teardown_class(cls):
        """Teardown the class after any methods"""
        cls.sinker = None
        cls.boto_mock.stop()

    def teardown(self):
        """Teardown the class after each methods"""
        self.sinker.env['lambda_alias'] = 'development'

    def test_streamsink_init(self):
        """StreamSink - Init"""
        assert_equal(self.sinker.function, 'corp-prefix_prod_streamalert_alert_processor')

    @patch('stream_alert.rule_processor.sink.LOGGER.exception')
    def test_streamsink_sink_boto_error(self, log_mock):
        """StreamSink - Boto Error"""

        err_response = {'Error': {'Code': 100}}

        # Add ClientError side_effect to mock
        self.boto_mock.return_value.invoke.side_effect = ClientError(
            err_response, 'operation')

        self.sinker.sink(['alert!!!'])

        log_mock.assert_called_with('An error occurred while sending alert to '
                                    '\'%s:production\'. Error is: %s. Alert: %s',
                                    'corp-prefix_prod_streamalert_alert_processor',
                                    err_response,
                                    '"alert!!!"')

    @patch('stream_alert.rule_processor.sink.LOGGER.error')
    def test_streamsink_sink_resp_error(self, log_mock):
        """StreamSink - Boto Response Error"""
        self.boto_mock.return_value.invoke.side_effect = [{
            'ResponseMetadata': {'HTTPStatusCode': 201}}]

        self.sinker.sink(['alert!!!'])

        log_mock.assert_called_with('Failed to send alert to \'%s\': %s',
                                    'corp-prefix_prod_streamalert_alert_processor',
                                    '"alert!!!"')

    @patch('stream_alert.rule_processor.sink.LOGGER.info')
    def test_streamsink_sink_success(self, log_mock):
        """StreamSink - Successful Sink"""
        self.boto_mock.return_value.invoke.side_effect = [{
            'ResponseMetadata': {
                'HTTPStatusCode': 202,
                'RequestId': 'reqID'
            }
        }]

        # Swap out the alias so the logging occurs
        self.sinker.env['lambda_alias'] = 'production'

        self.sinker.sink(['alert!!!'])

        log_mock.assert_called_with('Sent alert to \'%s\' with Lambda request ID \'%s\'',
                                    'corp-prefix_prod_streamalert_alert_processor',
                                    'reqID')

    @patch('stream_alert.rule_processor.sink.LOGGER.error')
    def test_streamsink_sink_bad_obj(self, log_mock):
        """StreamSink - JSON Dump Bad Object"""
        bad_object = datetime.utcnow()
        self.sinker.sink([bad_object])

        log_mock.assert_called_with(
            'An error occurred while dumping alert to JSON: %s Alert: %s',
            '\'datetime.datetime\' object has no attribute \'__dict__\'',
            bad_object)

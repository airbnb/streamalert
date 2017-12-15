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
# pylint: disable=protected-access,no-self-use
from mock import patch
from moto import mock_kinesis
from nose.tools import (assert_equal, assert_false, assert_true)

from stream_alert.rule_processor.config import load_config
from stream_alert.rule_processor.firehose import StreamAlertFirehose


@patch('stream_alert.rule_processor.firehose.StreamAlertFirehose.MAX_BACKOFF_ATTEMPTS', 1)
class TestStreamAlertFirehose(object):
    """Test class for StreamAlertFirehose"""

    def __init__(self):
        self.__sa_firehose = None

    def teardown(self):
        """Setup before each method"""
        self.__sa_firehose = None

    @staticmethod
    def _sample_categorized_payloads():
        return {
            'unit_test_simple_log': [{
                'unit_key_01': 1,
                'unit_key_02': 'test'
            }, {
                'unit_key_01': 2,
                'unit_key_02': 'test'
            }],
            'test_log_type_json_nested': [{
                'date': 'January 01, 3005',
                'unixtime': '32661446400',
                'host': 'my-host.name.website.com',
                'data': {
                    'super': 'secret'
                }
            }]
        }

    @mock_kinesis
    def _mock_delivery_streams(self, delivery_stream_names):
        """Mock Kinesis Delivery Streams for tests"""
        for delivery_stream in delivery_stream_names:
            self.__sa_firehose._firehose_client.create_delivery_stream(
                DeliveryStreamName=delivery_stream,
                S3DestinationConfiguration={
                    'RoleARN': 'arn:aws:iam::123456789012:role/firehose_delivery_role',
                    'BucketARN': 'arn:aws:s3:::kinesis-test',
                    'Prefix': '{}/'.format(delivery_stream),
                    'BufferingHints': {
                        'SizeInMBs': 123,
                        'IntervalInSeconds': 124
                    },
                    'CompressionFormat': 'Snappy',
                })

    @patch('stream_alert.rule_processor.firehose.LOGGER')
    @mock_kinesis
    def test_record_delivery_failed_put_count(self, mock_logging):
        """StreamAlertFirehose - Record Delivery - Failed Put Count"""
        self.__sa_firehose = StreamAlertFirehose(
            region='us-east-1', firehose_config={}, log_sources={})

        # Add sample categorized payloads
        for payload_type, logs in self._sample_categorized_payloads().iteritems():
            self.__sa_firehose.categorized_payloads[payload_type].extend(logs)

        # Setup mocked Delivery Streams
        self._mock_delivery_streams(
            ['streamalert_data_test_log_type_json_nested', 'streamalert_data_unit_test_simple_log'])

        with patch.object(self.__sa_firehose._firehose_client, 'put_record_batch') as firehose_mock:
            firehose_mock.side_effect = [{
                'FailedPutCount':
                3,
                'RequestResponses': [{
                    "ErrorCode": "ServiceUnavailableException",
                    "ErrorMessage": "Slow down."
                }, {
                    "ErrorCode": "ServiceUnavailableException",
                    "ErrorMessage": "Slow down."
                }, {
                    "ErrorCode": "ServiceUnavailableException",
                    "ErrorMessage": "Slow down."
                }]
            }, {
                'FailedPutCount':
                3,
                'RequestResponses': [{
                    "ErrorCode": "ServiceUnavailableException",
                    "ErrorMessage": "Slow down."
                }, {
                    "ErrorCode": "ServiceUnavailableException",
                    "ErrorMessage": "Slow down."
                }, {
                    "ErrorCode": "ServiceUnavailableException",
                    "ErrorMessage": "Slow down."
                }]
            }, {
                'FailedPutCount':
                0,
                'RequestResponses': [{
                    "RecordId": "12345678910",
                    "ErrorCode": "None",
                    "ErrorMessage": "None"
                }, {
                    "RecordId": "12345678910",
                    "ErrorCode": "None",
                    "ErrorMessage": "None"
                }, {
                    "RecordId": "12345678910",
                    "ErrorCode": "None",
                    "ErrorMessage": "None"
                }]
            }]
            self.__sa_firehose.send()

            firehose_mock.assert_called()
            assert_true(mock_logging.info.called)

    @patch('stream_alert.rule_processor.firehose.LOGGER')
    @mock_kinesis
    def test_record_delivery(self, mock_logging):
        """StreamAlertFirehose - Record Delivery"""
        self.__sa_firehose = StreamAlertFirehose(
            region='us-east-1', firehose_config={}, log_sources={})

        # Add sample categorized payloads
        for payload_type, logs in self._sample_categorized_payloads().iteritems():
            self.__sa_firehose.categorized_payloads[payload_type].extend(logs)

        # Setup mocked Delivery Streams
        self._mock_delivery_streams(
            ['streamalert_data_test_log_type_json_nested', 'streamalert_data_unit_test_simple_log'])

        # Send the records
        with patch.object(self.__sa_firehose._firehose_client, 'put_record_batch') as firehose_mock:
            firehose_mock.return_value = {'FailedPutCount': 0}
            self.__sa_firehose.send()

            firehose_mock.assert_called()
            assert_true(mock_logging.info.called)

    @patch('stream_alert.rule_processor.firehose.LOGGER')
    @mock_kinesis
    def test_record_delivery_failure(self, mock_logging):
        """StreamAlertFirehose - Record Delivery - Failed PutRecord"""
        self.__sa_firehose = StreamAlertFirehose(
            region='us-east-1', firehose_config={}, log_sources={})

        # Add sample categorized payloads
        for payload_type, logs in self._sample_categorized_payloads().iteritems():
            self.__sa_firehose.categorized_payloads[payload_type].extend(logs)

        # Setup mocked Delivery Streams
        self._mock_delivery_streams(
            ['streamalert_data_test_log_type_json_nested', 'streamalert_data_unit_test_simple_log'])

        # Send the records
        with patch.object(self.__sa_firehose._firehose_client, 'put_record_batch') as firehose_mock:
            firehose_mock.return_value = {
                'FailedPutCount':
                3,
                'RequestResponses': [
                    {
                        'RecordId': '12345',
                        'ErrorCode': '300',
                        'ErrorMessage': 'Bad message!!!'
                    },
                ]
            }
            self.__sa_firehose.send()

            firehose_mock.assert_called()
            assert_true(mock_logging.error.called)

    @patch('stream_alert.rule_processor.firehose.LOGGER')
    @mock_kinesis
    def test_record_delivery_client_error(self, mock_logging):
        """StreamAlertFirehose - Record Delivery - Client Error"""
        sa_firehose = StreamAlertFirehose(region='us-east-1', firehose_config={}, log_sources={})

        test_events = [
            # unit_test_simple_log
            {
                'unit_key_01': 2,
                'unit_key_02': 'testtest'
            } for _ in range(10)
        ]

        sa_firehose._firehose_request_helper('invalid_stream', test_events)

        missing_stream_message = 'Client Error ... An error occurred ' \
            '(ResourceNotFoundException) when calling the PutRecordBatch ' \
            'operation: Stream invalid_stream under account 123456789012 not found.'
        assert_true(mock_logging.error.called_with(missing_stream_message))

    @mock_kinesis
    def test_load_enabled_sources(self):
        """StreamAlertFirehose - Load Enabled Sources"""
        config = load_config('tests/unit/conf')
        firehose_config = {
            'enabled_logs': ['json:regex_key_with_envelope', 'test_cloudtrail', 'cloudwatch']
        }  # expands to 2 logs

        sa_firehose = StreamAlertFirehose(
            region='us-east-1', firehose_config=firehose_config, log_sources=config['logs'])

        assert_equal(len(sa_firehose._enabled_logs), 4)
        # Make sure the subtitution works properly
        assert_true(all([':' not in log for log in sa_firehose.enabled_logs]))
        assert_false(sa_firehose.enabled_log_source('test_inspec'))

    @patch('stream_alert.rule_processor.firehose.LOGGER')
    @mock_kinesis
    def test_load_enabled_sources_invalid_log(self, mock_logging):
        """StreamAlertFirehose - Load Enabled Sources - Invalid Log"""
        config = load_config('tests/unit/conf')
        firehose_config = {'enabled_logs': ['log-that-doesnt-exist']}

        sa_firehose = StreamAlertFirehose(
            region='us-east-1', firehose_config=firehose_config, log_sources=config['logs'])

        assert_equal(len(sa_firehose._enabled_logs), 0)
        assert_true(mock_logging.error.called)

    def test_segment_records_by_size(self):
        """StreamAlertFirehose - Segment Large Records"""
        sa_firehose = StreamAlertFirehose(region='us-east-1', firehose_config={}, log_sources={})

        record_batch = [
            # unit_test_simple_log
            {
                'unit_key_01': 2,
                'unit_key_02': 'testtest' * 10000
            } for _ in range(100)
        ]

        sized_batches = []

        for sized_batch in sa_firehose._segment_records_by_size(record_batch):
            sized_batches.append(sized_batch)

        assert_true(len(str(sized_batches[0])) < 4000000)
        assert_equal(len(sized_batches), 4)
        assert_true(isinstance(sized_batches[3][0], dict))

    def test_sanitize_keys(self):
        """StreamAlertFirehose - Sanitize Keys"""
        # test_log_type_json_nested
        test_event = {
            'date': 'January 01, 3005',
            'unixtime': '32661446400',
            'host': 'my-host.name.website.com',
            'data': {
                'super-duper': 'secret',
                'sanitize_me': 1,
                'example-key': 1,
                'moar**data': 2,
                'even.more': 3
            }
        }

        expected_sanitized_event = {
            'date': 'January 01, 3005',
            'unixtime': '32661446400',
            'host': 'my-host.name.website.com',
            'data': {
                'super_duper': 'secret',
                'sanitize_me': 1,
                'example_key': 1,
                'moar__data': 2,
                'even_more': 3
            }
        }

        sanitized_event = StreamAlertFirehose.sanitize_keys(test_event)
        assert_equal(sanitized_event, expected_sanitized_event)

    @patch('stream_alert.rule_processor.firehose.LOGGER')
    def test_limit_record_size(self, mock_logging):
        """StreamAlertFirehose - Record Size Check"""
        test_events = [
            # unit_test_simple_log
            {
                'unit_key_01': 1,
                'unit_key_02': 'test' * 250001  # is 4 bytes higher than max
            },
            {
                'unit_key_01': 2,
                'unit_key_02': 'test'
            },
            # test_log_type_json_nested
            {
                'date': 'January 01, 3005',
                'unixtime': '32661446400',
                'host': 'my-host.name.website.com',
                'data': {
                    'super': 'secret'
                }
            }
        ]

        StreamAlertFirehose._limit_record_size(test_events)

        assert_true(len(test_events), 2)
        assert_true(mock_logging.error.called)

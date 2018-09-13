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
from mock import patch
from moto import mock_kinesis
from nose.tools import assert_equal, assert_false, assert_true

from stream_alert.rule_processor.firehose import FirehoseClient
from stream_alert.shared.config import load_config


@patch('stream_alert.rule_processor.firehose.FirehoseClient.MAX_BACKOFF_ATTEMPTS', 1)
class TestFirehoseClient(object):
    """Test class for FirehoseClient"""
    # pylint: disable=protected-access,no-self-use,attribute-defined-outside-init

    def setup(self):
        """Setup before each method"""
        self.sa_firehose = FirehoseClient(region='us-east-1')

    def teardown(self):
        """Teardown after each method"""
        FirehoseClient._ENABLED_LOGS.clear()

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
            self.sa_firehose._client.create_delivery_stream(
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
        """FirehoseClient - Record Delivery - Failed Put Count"""
        # Add sample categorized payloads
        for payload_type, logs in self._sample_categorized_payloads().iteritems():
            self.sa_firehose._categorized_payloads[payload_type].extend(logs)

        # Setup mocked Delivery Streams
        self._mock_delivery_streams(
            ['streamalert_data_test_log_type_json_nested', 'streamalert_data_unit_test_simple_log'])

        with patch.object(self.sa_firehose._client, 'put_record_batch') as firehose_mock:
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
            self.sa_firehose.send()

            firehose_mock.assert_called()
            assert_true(mock_logging.info.called)

    @patch('stream_alert.rule_processor.firehose.LOGGER')
    @mock_kinesis
    def test_record_delivery(self, mock_logging):
        """FirehoseClient - Record Delivery"""
        # Add sample categorized payloads
        for payload_type, logs in self._sample_categorized_payloads().iteritems():
            self.sa_firehose._categorized_payloads[payload_type].extend(logs)

        # Setup mocked Delivery Streams
        self._mock_delivery_streams(
            ['streamalert_data_test_log_type_json_nested', 'streamalert_data_unit_test_simple_log'])

        # Send the records
        with patch.object(self.sa_firehose._client, 'put_record_batch') as firehose_mock:
            firehose_mock.return_value = {'FailedPutCount': 0}
            self.sa_firehose.send()

            firehose_mock.assert_called()
            assert_true(mock_logging.info.called)

    @patch('stream_alert.rule_processor.firehose.LOGGER')
    @mock_kinesis
    def test_record_delivery_failure(self, mock_logging):
        """FirehoseClient - Record Delivery - Failed PutRecord"""
        # Add sample categorized payloads
        for payload_type, logs in self._sample_categorized_payloads().iteritems():
            self.sa_firehose._categorized_payloads[payload_type].extend(logs)

        # Setup mocked Delivery Streams
        self._mock_delivery_streams(
            ['streamalert_data_test_log_type_json_nested', 'streamalert_data_unit_test_simple_log'])

        # Send the records
        with patch.object(self.sa_firehose._client, 'put_record_batch') as firehose_mock:
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
            self.sa_firehose.send()

            firehose_mock.assert_called()
            assert_true(mock_logging.error.called)

    @patch('stream_alert.rule_processor.firehose.LOGGER')
    @mock_kinesis
    def test_record_delivery_client_error(self, mock_logging):
        """FirehoseClient - Record Delivery - Client Error"""
        test_events = [
            # unit_test_simple_log
            {
                'unit_key_01': 2,
                'unit_key_02': 'testtest'
            } for _ in range(10)
        ]

        self.sa_firehose._firehose_request_helper('invalid_stream', test_events)

        missing_stream_message = 'Client Error ... An error occurred ' \
            '(ResourceNotFoundException) when calling the PutRecordBatch ' \
            'operation: Stream invalid_stream under account 123456789012 not found.'
        assert_true(mock_logging.error.called_with(missing_stream_message))

    @mock_kinesis
    def test_load_enabled_sources(self):
        """FirehoseClient - Load Enabled Sources"""
        config = load_config('tests/unit/conf')
        firehose_config = {
            'enabled_logs': ['json:regex_key_with_envelope', 'test_cloudtrail', 'cloudwatch']
        }  # expands to 2 logs

        enabled_logs = FirehoseClient.load_enabled_log_sources(firehose_config, config['logs'])

        assert_equal(len(enabled_logs), 4)
        # Make sure the subtitution works properly
        assert_true(all([':' not in log for log in enabled_logs]))
        assert_false(FirehoseClient.enabled_log_source('test_inspec'))

    @patch('stream_alert.rule_processor.firehose.LOGGER.error')
    @mock_kinesis
    def test_load_enabled_sources_invalid_log(self, mock_logging):
        """FirehoseClient - Load Enabled Sources - Invalid Log"""
        config = load_config('tests/unit/conf')
        firehose_config = {'enabled_logs': ['log-that-doesnt-exist']}

        sa_firehose = FirehoseClient(
            region='us-east-1', firehose_config=firehose_config, log_sources=config['logs'])

        assert_equal(len(sa_firehose._ENABLED_LOGS), 0)
        mock_logging.assert_called_with(
            'Enabled Firehose log %s not declared in logs.json', 'log-that-doesnt-exist'
        )

    def test_strip_successful_records(self):
        """FirehoseClient - Strip Successful Records"""
        batch = [{'test': 'success'}, {'test': 'data'}, {'other': 'failure'}, {'other': 'info'}]
        response = {
            'FailedPutCount': 1,
            'RequestResponses': [
                {'RecordId': 'rec_id_00'},
                {'RecordId': 'rec_id_01'},
                {'ErrorCode': 10, 'ErrorMessage': 'foo'},
                {'RecordId': 'rec_id_03'}
            ]
        }

        expected_batch = [{'other': 'failure'}]
        FirehoseClient._strip_successful_records(batch, response)

        assert_equal(batch, expected_batch)

    def test_segment_records_by_size(self):
        """FirehoseClient - Segment Large Records"""
        record_batch = [
            # unit_test_simple_log
            {
                'unit_key_01': 2,
                'unit_key_02': 'testtest' * 10000
            } for _ in range(100)
        ]

        sized_batches = []

        for sized_batch in FirehoseClient._segment_records_by_size(record_batch):
            sized_batches.append(sized_batch)

        assert_true(len(str(sized_batches[0])) < 4000000)
        assert_equal(len(sized_batches), 4)
        assert_true(isinstance(sized_batches[3][0], dict))

    def test_sanitize_keys(self):
        """FirehoseClient - Sanitize Keys"""
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

        sanitized_event = FirehoseClient.sanitize_keys(test_event)
        assert_equal(sanitized_event, expected_sanitized_event)

    @patch('stream_alert.rule_processor.firehose.LOGGER')
    def test_limit_record_size(self, mock_logging):
        """FirehoseClient - Record Size Check"""
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
            },
            # add another unit_test_sample_log to verify in a different position
            {
                'unit_key_01': 1,
                'unit_key_02': 'test' * 250001  # is 4 bytes higher than max
            },
            {
                'test': 1
            }
        ]

        FirehoseClient._limit_record_size(test_events)

        assert_true(len(test_events), 3)
        assert_true(mock_logging.error.called)

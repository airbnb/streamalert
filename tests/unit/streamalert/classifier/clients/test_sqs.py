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
from botocore.exceptions import ClientError
from mock import Mock, patch
from nose.tools import assert_equal, assert_raises

import stream_alert.classifier.clients.sqs as sqs
from stream_alert.classifier.clients.sqs import SQSClient, SQSClientError


class TestSQSClient(object):
    """Test class for SQSClient"""
    # pylint: disable=protected-access,no-self-use,attribute-defined-outside-init

    def setup(self):
        """SQSClient - Setup"""
        # patch to speed up unit tests slightly
        with patch('boto3.resource'), \
             patch.dict('os.environ', {'SQS_QUEUE_URL': 'test_url'}):

            self._client = SQSClient()

    def teardown(self):
        """Teardown after each method"""
        SQSClient._queue = None

    @classmethod
    def _sample_batch(cls, count=1):
        return [
            {'Id': str(i), 'MessageBody': 'value_{}'.format(i)}
            for i in range(count)
        ]

    def _sample_payloads(self, count=1):
        return [
            Mock(
                sqs_messages=[
                    {
                        'log_schema_type': 'log_type_{}'.format(i),
                        'record': {
                            'key_{}'.format(i): 'value_{}'.format(i)
                        }
                    }
                ]
            ) for i in range(count)
        ]

    @classmethod
    def _sample_raw_records(cls, count=2):
        return [
            {'key_{}'.format(i): 'value_{}'.format(i)}
            for i in range(count)
        ]

    def test_init_no_queue_url(self):
        """SQSClient - Init, No URL in Environment"""
        assert_raises(SQSClientError, SQSClient)

    def test_queue_property(self):
        """SQSClient - Queue Property"""
        queue = 'test_queue'
        SQSClient._queue = queue
        assert_equal(self._client.queue, queue)

    def test_log_failed(self):
        """SQSClient - Log Failed"""
        with patch.object(sqs.MetricLogger, 'log_metric') as metric_mock:
            SQSClient._log_failed(1)
            metric_mock.assert_called_with('classifier', 'SQSFailedRecords', 1)

    def test_message_batches(self):
        """SQSClient - Message Batches"""
        records = self._sample_raw_records()

        expected_result = [
            [
                '{"key_0":"value_0"}',
                '{"key_1":"value_1"}'
            ]
        ]

        result = list(SQSClient._message_batches(records))
        assert_equal(result, expected_result)

    @patch.object(SQSClient, '_log_failed')
    def test_message_batches_rec_too_large(self, failure_mock):
        """SQSClient - Message Batches, Record Too Large"""
        records = [
            {'key': 'test' * 1000 * 100}
        ]

        result = list(SQSClient._message_batches(records))
        assert_equal(result, [[]])
        failure_mock.assert_called_with(1)

    def test_message_batches_max_batch_count(self):
        """SQSClient - Message Batches, Max Batch Count"""
        records = self._sample_raw_records(count=11)

        result = list(SQSClient._message_batches(records))
        assert_equal(len(result), 2)
        assert_equal(len(result[0]), 10)
        assert_equal(len(result[1]), 1)

    def test_message_batches_max_batch_size(self):
        """SQSClient - Message Batches, Max Batch Size"""
        records = [
            {'key_{}'.format(i): 'test' * 10000}
            for i in range(10)
        ]
        result = list(SQSClient._message_batches(records))
        assert_equal(len(result), 2)
        assert_equal(len(result[0]), 6)
        assert_equal(len(result[1]), 4)
        batch_size_01 = sum(len(rec) for rec in result[0])
        batch_size_02 = sum(len(rec) for rec in result[1])
        assert_equal(batch_size_01 < SQSClient.MAX_BATCH_SIZE, True)
        assert_equal(batch_size_02 < SQSClient.MAX_BATCH_SIZE, True)
        assert_equal(batch_size_01 + batch_size_02 > SQSClient.MAX_BATCH_SIZE, True)

    def test_format_failure_message(self):
        """SQSClient - Format Failure Message"""
        failure = {
            'Id': '1',
            'Code': 'error code',
            'Message': 'error message',
            'SenderFault': True
        }
        expected_result = (
            'Record failed to send to SQS. ID: 1, SenderFault: True, '
            'Code: error code, Error: error message'
        )

        message = SQSClient._format_failure_message(failure)
        assert_equal(message, expected_result)

    def test_format_failure_message_with_record(self):
        """SQSClient - Format Failure Message, With Record"""
        failure = {
            'Id': '1',
            'Code': 'error code',
            'Message': 'error message',
            'SenderFault': True
        }

        record = 'data'
        expected_result = (
            'Record failed to send to SQS. ID: 1, SenderFault: True, '
            'Code: error code, Error: error message, Record:\ndata'
        )

        message = SQSClient._format_failure_message(failure, record)
        assert_equal(message, expected_result)

    @patch('logging.Logger.info')
    @patch.object(SQSClient, '_log_failed')
    def test_finalize_failures(self, failure_mock, log_mock):
        """SQSClient - Finalize, With Failures"""
        batch = self._sample_batch(2)
        response = {
            'Successful': [
                {
                    'Id': '0'
                }
            ],
            'Failed': [
                {
                    'Id': '1',
                    'SenderFault': False,
                    'Code': 'error code',
                    'Message': 'error message'
                }
            ]
        }

        url = 'test_url'
        SQSClient._queue.url = url
        self._client._finalize(response, batch)  # None, None to represent 2 records

        failure_mock.assert_called_with(1)
        log_mock.assert_called_with('Successfully sent %d messages to SQS Queue: %s', 1, url)

    @patch('logging.Logger.info')
    def test_finalize_success(self, log_mock):
        """SQSClient - Finalize, Success"""
        batch = self._sample_batch(1)
        response = {
            'Successful': [
                {
                    'Id': '0'
                }
            ]
        }

        url = 'test_url'
        SQSClient._queue.url = url
        self._client._finalize(response, batch)

        log_mock.assert_called_with('Successfully sent %d messages to SQS Queue: %s', 1, url)

    def test_strip_successful_records(self):
        """SQSClient - Strip Successful Records"""
        batch = self._sample_batch(2)
        response = {
            'Successful': [
                {
                    'Id': '0'
                }
            ],
            'Failed': [
                {
                    'Id': '1',
                    'SenderFault': False,
                    'Code': 'error code',
                    'Message': 'error message'
                }
            ]
        }

        expected_batch = [{'Id': '1', 'MessageBody': 'value_1'}]
        SQSClient._strip_successful_records(batch, response)

        assert_equal(batch, expected_batch)

    def test_extract_message_by_id(self):
        """SQSClient - Extract Message by ID"""
        batch = self._sample_batch(2)
        expected_message = batch[1]

        result = SQSClient._extract_message_by_id(batch, '1')
        assert_equal(result, expected_message)

    @patch('logging.Logger.error')
    def test_extract_message_by_id_invalid(self, log_mock):
        """SQSClient - Extract Message by ID, Invalid"""
        batch = self._sample_batch(2)

        result = SQSClient._extract_message_by_id(batch, '2')
        assert_equal(result, None)
        log_mock.assert_called_with('SQS message with ID \'%s\' not found in batch', '2')

    def test_check_failures_none(self):
        """SQSClient - Check Failures, None"""
        response = {
            'Successful': [
                {
                    'Id': '0'
                }
            ],
            'Failed': []
        }

        result = self._client._check_failures(response)
        assert_equal(result, 0)

    def test_check_failures_sender_fault(self):
        """SQSClient - Check Failures, Sender Fault"""
        response = {
            'Successful': [],
            'Failed': [
                {
                    'Id': '1',
                    'SenderFault': True,
                    'Code': 'error code',
                    'Message': 'error message'
                }
            ]
        }
        assert_raises(SQSClientError, self._client._check_failures, response)

    def test_check_failures_not_sender_fault(self):
        """SQSClient - Check Failures, Not Sender Fault"""
        response = {
            'Successful': [],
            'Failed': [
                {
                    'Id': '1',
                    'SenderFault': False,
                    'Code': 'error code',
                    'Message': 'error message'
                }
            ]
        }
        result = self._client._check_failures(response)
        assert_equal(result, 1)

    @patch('logging.Logger.error')
    def test_check_failures_with_record(self, log_mock):
        """SQSClient - Check Failures, With Record"""
        batch = self._sample_batch(2)
        response = {
            'Successful': [],
            'Failed': [
                {
                    'Id': '1',
                    'SenderFault': False,
                    'Code': 'error code',
                    'Message': 'error message'
                }
            ]
        }

        SQSClient._queue.url = 'test_url'
        result = self._client._check_failures(response, batch)

        assert_equal(result, 1)
        log_mock.assert_called_with(
            'Record failed to send to SQS. ID: 1, SenderFault: False, Code: error code, '
            'Error: error message, Record:\n{\'Id\': \'1\', \'MessageBody\': \'value_1\'}'
        )

    @patch.object(SQSClient, 'MAX_BACKOFF_ATTEMPTS', 1)
    def test_send_messages(self):
        """SQSClient - Send Messages"""
        records = [
            'test_message_00',
            'test_message_01',
            'test_message_02'
        ]

        SQSClient._queue.send_messages.side_effect = [
            {
                'Successful': [
                    {'Id': '0'},
                    {'Id': '2'}
                ],
                'Failed': [
                    {
                        'Id': '1',
                        'Code': 'error',
                        'Message': 'message',
                        'SenderFault': False
                    }
                ]
            },
            {
                'Successful': [
                    {'Id': '1'}
                ]
            }
        ]

        expected_second_call = [
            {
                'Id': '1',
                'MessageBody': 'test_message_01'
            }
        ]

        self._client._send_messages(records)

        SQSClient._queue.send_messages.assert_called_with(
            Entries=expected_second_call
        )

    @patch('logging.Logger.exception')
    @patch.object(SQSClient, 'MAX_BACKOFF_ATTEMPTS', 1)
    def test_send_messages_error(self, log_mock):
        """SQSClient - Send Messages, Error"""
        error = ClientError({'Error': {'Code': 10}}, 'InvalidRequestException')
        SQSClient._queue.send_messages.side_effect = error

        self._client._send_messages(['data'])

        log_mock.assert_called_with('SQS request failed')

    def test_payload_messages(self):
        """SQSClient - Payload Records"""
        payloads = self._sample_payloads()
        expected_result = [{
            'log_schema_type': 'log_type_0',
            'record': {
                'key_0': 'value_0'
            }
        }]
        result = SQSClient._payload_messages(payloads)
        assert_equal(result, expected_result)

    @patch.object(SQSClient, '_send_messages')
    def test_send(self, send_messages_mock):
        """SQSClient - Send"""
        payloads = self._sample_payloads()
        expected_batch = [
            '{"log_schema_type":"log_type_0","record":{"key_0":"value_0"}}'
        ]
        self._client.send(payloads)
        send_messages_mock.assert_called_with(expected_batch)

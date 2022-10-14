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
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError

import streamalert.classifier.clients.sqs as sqs
from streamalert.classifier.clients.sqs import SQSClient, SQSClientError


class TestSQSClient:
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

    def _sample_payloads(self, count=1):
        return [Mock(sqs_messages=[{'log_schema_type': f'log_type_{i}',
                                    'record': {f'key_{i}': f'value_{i}'}}]) for i in range(count)]

    def test_init_no_queue_url(self):
        """SQSClient - Init, No URL in Environment"""
        pytest.raises(SQSClientError, SQSClient)

    def test_queue_property(self):
        """SQSClient - Queue Property"""
        queue = 'test_queue'
        SQSClient._queue = queue
        assert self._client.queue == queue

    @patch('logging.Logger.debug')
    def test_segment_records_no_segmentation(self, log_mock):
        """SQSClient - Segment Records, No Segmentation"""
        records = ['{"key":"value"}']
        result = list(SQSClient._segment_records(records))
        expected_result = [(['{"key":"value"}'], 1)]
        assert result == expected_result
        log_mock.assert_not_called()

    @patch('logging.Logger.error')
    def test_segment_records_too_large(self, log_mock):
        """SQSClient - Segment Records, Single Record Too Large"""
        large_value = 'value' * 52428
        records = ['{{"key":"{}"}}'.format(large_value)]  # a single record that exceeds max size
        recs = records[:]
        result = list(SQSClient._segment_records(records))
        assert not result
        log_mock.assert_called_with('Record is too large to send to SQS:\n%s', recs[0])

    @patch('logging.Logger.error')
    def test_segment_records_one_too_large(self, log_mock):
        """SQSClient - Segment Records, Record Too Large"""
        # A record that exceeds max size and one that does not
        large_value = 'value' * 52428
        records = ['{{"key":"{}"}}'.format(large_value), '{"key":"value"}']
        result = list(SQSClient._segment_records(records))
        expected_result = [(['{"key":"value"}'], 1)]
        assert result == expected_result
        log_mock.assert_called_with('Record is too large to send to SQS:\n%s', records[0])

    def test_segment_records_multiple_sets(self):
        """SQSClient - Segment Records, Multiple Sets"""
        # A record that exceeds max size and some that do not
        large_rec = '{{"key":"{}"}}'.format('value' * 52426)
        small_rec = '{"key":"value"}'
        records = [large_rec] + ([small_rec] * 3)

        result = list(SQSClient._segment_records(records))

        expected_result = [
            ([large_rec], 1),
            ([small_rec] * 3, 3)
        ]

        assert result == expected_result

    def test_segment_records_last_record(self):
        """SQSClient - Segment Records, Last Record"""
        # A record that exceeds max size and some that do not
        large_rec = '{{"key":"{}"}}'.format('value' * 52426)
        small_rec = '{"key":"value"}'
        records = [large_rec, small_rec]

        result = list(SQSClient._segment_records(records))

        expected_result = [
            ([large_rec], 1),
            ([small_rec], 1)
        ]

        assert result == expected_result

    @patch.object(sqs.MetricLogger, 'log_metric')
    def test_finalize_failures(self, metric_mock):
        """SQSClient - Finalize, With Failures"""
        self._client._finalize(False, 10)  # None, None to represent 2 records
        metric_mock.assert_called_with('classifier', 'SQSFailedRecords', 10)

    @patch('logging.Logger.debug')
    def test_finalize_success(self, log_mock):
        """SQSClient - Finalize, Success"""
        response = '8fb984ee-b44c-4a68-992f-4f7aae23ae07'
        url = 'test_url'
        SQSClient._queue.url = url
        self._client._finalize(response, 10)

        log_mock.assert_called_with(
            'Successfully sent message with %d records to %s with MessageId %s',
            10,
            url,
            response
        )

    @patch.object(SQSClient, 'MAX_BACKOFF_ATTEMPTS', 1)
    def test_send_message(self):
        """SQSClient - Send Messages"""
        records = [
            'test_message_00',
            'test_message_01'
        ]

        SQSClient._queue.send_message.side_effect = [
            {
                'MD5OfMessageBody': '8d110f3d795665a3b26cac774b995170',
                'MD5OfMessageAttributes': '8cac774b995170d110f3d795665a3b26',
                'MessageId': '8fb984ee-b44c-4a68-992f-4f7aae23ae07',
                'SequenceNumber': '0'
            }
        ]

        expected_call = {
            'MessageBody': '[test_message_00,test_message_01]'
        }

        self._client._send_message(records)

        SQSClient._queue.send_message.assert_called_with(**expected_call)

    @patch('logging.Logger.exception')
    @patch.object(SQSClient, 'MAX_BACKOFF_ATTEMPTS', 1)
    def test_send_messages_error(self, log_mock):
        """SQSClient - Send Messages, Error"""
        error = ClientError({'Error': {'Code': 10}}, 'InvalidRequestException')
        SQSClient._queue.send_message.side_effect = error

        assert self._client._send_message(['data']) == False
        log_mock.assert_called_with('SQS request failed')

    def test_payload_messages(self):
        """SQSClient - Payload Records"""
        payloads = self._sample_payloads()
        expected_result = [
            '{"log_schema_type":"log_type_0","record":{"key_0":"value_0"}}'
        ]
        result = SQSClient._payload_messages(payloads)
        assert result == expected_result

    @patch.object(SQSClient, '_send_message')
    def test_send(self, send_message_mock):
        """SQSClient - Send"""
        payloads = self._sample_payloads()
        expected_batch = [
            '{"log_schema_type":"log_type_0","record":{"key_0":"value_0"}}'
        ]
        self._client.send(payloads)
        send_message_mock.assert_called_with(expected_batch)

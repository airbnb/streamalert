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
# pylint: disable=attribute-defined-outside-init,protected-access
import json
import os

import boto3
from mock import Mock, patch
from moto import mock_sqs
from nose.tools import (
    assert_equal,
    assert_false,
    assert_is_instance,
    assert_is_none,
    assert_true
)

from stream_alert.athena_partition_refresh.main import StreamAlertSQSClient
from stream_alert.shared.config import load_config


# Without this time.sleep patch, backoff performs sleep
# operations and drastically slows down testing
@patch('time.sleep', Mock())
@patch.object(StreamAlertSQSClient, 'SQS_BACKOFF_MAX_RETRIES', 1)
class TestStreamAlertSQSClient(object):
    """Test class for StreamAlertSQSClient"""

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-west-1'})
    def setup(self):
        """Add a fake message to the queue."""
        self.mock_sqs = mock_sqs()
        self.mock_sqs.start()

        sqs = boto3.resource('sqs')

        config = load_config('tests/unit/conf/')
        prefix = config['global']['account']['prefix']
        name = StreamAlertSQSClient.DEFAULT_QUEUE_NAME.format(prefix)

        self.queue = sqs.create_queue(QueueName=name)

        # Create a fake s3 notification message to send
        bucket = 'unit-testing.streamalerts'
        test_s3_notification = {
            'Records': [
                {
                    'eventVersion': '2.0',
                    'eventSource': 'aws:s3',
                    'awsRegion': 'us-east-1',
                    'eventTime': '2017-08-07T18:26:30.956Z',
                    'eventName': 'S3:PutObject',
                    'userIdentity': {
                        'principalId': 'AWS:AAAAAAAAAAAAAAA'
                    },
                    'requestParameters': {
                        'sourceIPAddress': '127.0.0.1'
                    },
                    'responseElements': {
                        'x-amz-request-id': 'FOO',
                        'x-amz-id-2': 'BAR'
                    },
                    's3': {
                        's3SchemaVersion': '1.0',
                        'configurationId': 'queue',
                        'bucket': {
                            'name': bucket,
                            'ownerIdentity': {
                                'principalId': 'AAAAAAAAAAAAAAA'
                            },
                            'arn': 'arn:aws:s3:::{}'.format(bucket)
                        },
                        'object': {
                            'key': ('alerts/dt=2017-08-2{}-14-02/rule_name_alerts-'
                                    '1304134918401.json'.format(day)),
                            'size': 1494,
                            'eTag': '12214134141431431',
                            'versionId': 'asdfasdfasdf.dfadCJkj1',
                            'sequencer': '1212312321312321321'
                        }
                    }
                }
                for day in {6, 7}
            ]
        }
        self.queue.send_message(MessageBody=json.dumps(test_s3_notification))

        self.client = StreamAlertSQSClient(config)

    def teardown(self):
        """Purge the Queue and reset the client between runs"""
        self.mock_sqs.stop()

    @patch('logging.Logger.error')
    def test_delete_messages_none_received(self, mock_logging):
        """Athena SQS - Delete Messages - No Receieved Messages"""
        self.client.delete_messages()
        assert_true(mock_logging.called)

    @patch('logging.Logger.error')
    def test_delete_messages_failure_retries(self, log_mock):
        """Athena SQS - Delete Messages - Failure Response and push back messages to queue"""
        with patch.object(self.client.sqs_client, 'delete_message_batch') as sqs_mock:
            sqs_mock.return_value = {'Failed': [{'Id': '1'}]}

            self.client.processed_messages = [{'MessageId': '1', 'ReceiptHandle': 'handle1'},
                                              {'MessageId': '2', 'ReceiptHandle': 'handle2'}]
            self.client.delete_messages()
            for message in self.client.processed_messages:
                assert_is_instance(message, dict)

            assert_true(log_mock.called_with('Failed to delete the messages with following'))

    @patch('logging.Logger.error')
    def test_delete_messages_none_processed(self, log_mock):
        """Athena SQS - Delete Messages - No Processed Messages"""
        self.client.processed_messages = []
        result = self.client.delete_messages()

        assert_true(log_mock.called)
        assert_false(result)

    @patch('logging.Logger.info')
    def test_delete_messages(self, log_mock):
        """Athena SQS - Delete Messages"""
        self.client.get_messages(max_tries=1)
        self.client.unique_s3_buckets_and_keys()
        self.client.delete_messages()

        assert_true(log_mock.called)

    @patch('logging.Logger.error')
    def test_get_messages_invalid_max_messages(self, log_mock):
        """Athena SQS - Invalid Max Message Request"""
        resp = self.client.get_messages(max_messages=100)

        assert_true(log_mock.called)
        assert_is_none(resp)

    @patch('logging.Logger.info')
    def test_get_messages(self, log_mock):
        """Athena SQS - Get Valid Messages"""
        self.client.get_messages(max_tries=1)

        assert_equal(len(self.client.received_messages), 1)
        assert_true(log_mock.called)

    def test_unique_s3_buckets_and_keys(self):
        """Athena SQS - Get Unique Bucket Ids"""
        self.client.get_messages(max_tries=1)
        unique_buckets = self.client.unique_s3_buckets_and_keys()

        assert_equal(unique_buckets, {
            'unit-testing.streamalerts': set([
                'alerts/dt=2017-08-26-14-02/rule_name_alerts-1304134918401.json',
                'alerts/dt=2017-08-27-14-02/rule_name_alerts-1304134918401.json',
            ])
        })
        assert_equal(len(self.client.processed_messages), 2)

    @patch('logging.Logger.error')
    def test_unique_s3_buckets_and_keys_invalid_sqs(self, log_mock):
        """Athena SQS - Unique Buckets - Invalid SQS Message"""
        self.client.received_messages = ['wrong-format-test']
        unique_buckets = self.client.unique_s3_buckets_and_keys()

        assert_false(unique_buckets)
        assert_true(log_mock.called)

    @patch('logging.Logger.debug')
    def test_unique_s3_buckets_and_keys_s3_test_event(self, log_mock):
        """Athena SQS - Unique Buckets - S3 Test Event"""
        s3_test_event = {'Body': json.dumps({
            'HostId': '8cLeGAmw098X5cv4Zkwcmo8vvZa3eH3eKxsPzbB9wrR+YstdA6Knx4Ip8EXAMPLE',
            'Service': 'Amazon S3',
            'Bucket': 'bucketname',
            'RequestId': '5582815E1AEA5ADF',
            'Time': '2014-10-13T15:57:02.089Z',
            'Event': 's3:TestEvent'})}
        self.client.received_messages = [s3_test_event]
        unique_buckets = self.client.unique_s3_buckets_and_keys()

        assert_false(unique_buckets)
        assert_true(log_mock.called_with(
            'Skipping S3 bucket notification test event'))

    @patch('logging.Logger.error')
    def test_unique_s3_buckets_and_keys_invalid_record(self, log_mock):
        """Athena SQS - Unique Buckets - Missing Records Key in SQS Message"""
        self.client.received_messages = [{'Body': '{"missing-records-key": 1}'}]
        unique_buckets = self.client.unique_s3_buckets_and_keys()

        assert_false(unique_buckets)
        assert_true(log_mock.called)

    @patch('logging.Logger.info')
    @patch('logging.Logger.debug')
    def test_unique_s3_buckets_and_keys_non_s3_notification(self, log_debug_mock, log_info_mock):
        """Athena SQS - Unique Buckets - Non S3 Notification"""
        self.client.received_messages = [{'Body': '{"Records": [{"kinesis": 1}]}'}]
        unique_buckets = self.client.unique_s3_buckets_and_keys()

        assert_false(unique_buckets)
        assert_true(log_debug_mock.called)
        log_info_mock.assert_called_with('Skipping non-s3 bucket notification message')

    @patch('logging.Logger.error')
    def test_unique_s3_buckets_and_keys_no_mesages(self, log_mock):
        """Athena SQS - Unique Buckets - No Receieved Messages"""
        self.client.received_messages = []
        unique_buckets = self.client.unique_s3_buckets_and_keys()

        assert_is_none(unique_buckets)
        assert_true(log_mock.called)

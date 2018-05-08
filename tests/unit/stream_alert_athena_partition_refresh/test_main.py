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
from mock import call, Mock, patch
from moto import mock_sqs
from nose.tools import assert_equal, assert_true

from stream_alert.athena_partition_refresh.clients import StreamAlertSQSClient
from stream_alert.athena_partition_refresh.main import AthenaRefresher
from stream_alert.shared.config import load_config

from tests.unit.helpers.aws_mocks import MockAthenaClient


@patch('logging.Logger.error')
def test_init_logging_bad(log_mock):
    """Athena Parition Refresh Init - Logging, Bad Level"""
    level = 'IFNO'
    with patch.dict(os.environ, {'LOGGER_LEVEL': level}):
        import stream_alert.athena_partition_refresh
        reload(stream_alert.athena_partition_refresh)

        message = str(call('Defaulting to INFO logging: %s',
                           ValueError('Unknown level: \'IFNO\'',)))

        assert_equal(str(log_mock.call_args_list[0]), message)


@patch('stream_alert.athena_partition_refresh.LOGGER.setLevel')
def test_init_logging_int_level(log_mock):
    """Athena Parition Refresh Init - Logging, Integer Level"""
    with patch.dict(os.environ, {'LOGGER_LEVEL': '10'}):
        import stream_alert.athena_partition_refresh
        reload(stream_alert.athena_partition_refresh)
        log_mock.assert_called_with(10)


# Without this time.sleep patch, backoff performs sleep
# operations and drastically slows down testing
@patch('time.sleep', Mock())
class TestAthenaRefresher(object):
    """Test class for AthenaRefresher"""

    @patch('stream_alert.athena_partition_refresh.main.load_config',
           Mock(return_value=load_config('tests/unit/conf/')))
    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    @patch('stream_alert.shared.athena.boto3')
    def setup(self, boto_patch):
        """Setup the AthenaRefresher tests"""
        self.mock_sqs = mock_sqs()
        self.mock_sqs.start()
        boto_patch.client.return_value = MockAthenaClient()
        sqs = boto3.resource('sqs')
        name = StreamAlertSQSClient.DEFAULT_QUEUE_NAME.format('unit-testing')
        self.queue = sqs.create_queue(QueueName=name)
        self._refresher = AthenaRefresher()

    def teardown(self):
        """Teardown the AthenaRefresher tests"""
        self.mock_sqs.stop()

    def test_add_partitions(self):
        """AthenaRefresher - Add Partitions"""
        result = self._refresher._add_partition({
            'unit-testing.streamalerts': {
                'alerts/dt=2017-08-26-14/rule_name_alerts-1304134918401.json',
                'alerts/dt=2017-08-27-14/rule_name_alerts-1304134918401.json'
            },
            'unit-testing.streamalert.data': {
                'log_type_1/2017/08/26/14/test-data-11111-22222-33333.snappy',
                'log_type_2/2017/08/26/14/test-data-11111-22222-33333.snappy',
                'log_type_2/2017/08/26/15/test-data-11111-22222-33333.snappy',
                'log_type_2/2017/08/26/16/test-data-11111-22222-33333.snappy',
                'log_type_3/2017/08/26/14/test-data-11111-22222-33333.snappy',
                'log_type_1/2017/08/26/11/test-data-11111-22222-33333.snappy'
            },
            'test-bucket-with-data': {
                '2017/08/26/14/rule_name_alerts-1304134918401.json',
                '2017/08/28/14/rule_name_alerts-1304134918401.json',
                '2017/07/30/14/rule_name_alerts-1304134918401.json'
            }
        })

        assert_true(result)

    @patch('logging.Logger.error')
    def test_add_partitions_none(self, log_mock):
        """AthenaRefresher - Add Partitions, None to Add"""
        result = self._refresher._add_partition({})
        log_mock.assert_called_with('No partitons to add')
        assert_equal(result, False)

    def test_get_partitions_from_keys(self):
        """AthenaRefresher - Get Partitions From Keys"""
        expected_result = {
            'alerts': {
                '(dt = \'2017-08-26-14\')': ('\'s3://unit-testing.streamalerts/'
                                             'alerts/dt=2017-08-26-14\''),
                '(dt = \'2017-08-27-14\')': ('\'s3://unit-testing.streamalerts/'
                                             'alerts/dt=2017-08-27-14\''),
                '(dt = \'2017-08-26-15\')': ('\'s3://unit-testing.streamalerts/'
                                             'alerts/2017/08/26/15\'')
            },
            'log_type_1': {
                '(dt = \'2017-08-26-14\')': ('\'s3://unit-testing.streamalert.data/'
                                             'log_type_1/2017/08/26/14\'')
            },
            'log_type_2': {
                '(dt = \'2017-08-26-14\')': ('\'s3://unit-testing.streamalert.data/'
                                             'log_type_2/2017/08/26/14\''),
                '(dt = \'2017-08-26-15\')': ('\'s3://unit-testing.streamalert.data/'
                                             'log_type_2/2017/08/26/15\''),
                '(dt = \'2017-08-26-16\')': ('\'s3://unit-testing.streamalert.data/'
                                             'log_type_2/2017/08/26/16\''),
            },
            'log_type_3': {
                '(dt = \'2017-08-26-14\')': ('\'s3://unit-testing.streamalert.data/'
                                             'log_type_3/2017/08/26/14\''),
            }
        }

        result = self._refresher._get_partitions_from_keys({
            'unit-testing.streamalerts': {
                'alerts/dt=2017-08-26-14/rule_name_alerts-1304134918401.json',
                'alerts/dt=2017-08-27-14/rule_name_alerts-1304134918401.json',
                'alerts/2017/08/26/15/rule_name_alerts-1304134918401.json'
            },
            'unit-testing.streamalert.data': {
                'log_type_1/2017/08/26/14/test-data-11111-22222-33333.snappy',
                'log_type_2/2017/08/26/14/test-data-11111-22222-33333.snappy',
                'log_type_2/2017/08/26/14/test-data-11111-22222-33334.snappy',
                'log_type_2/2017/08/26/15/test-data-11111-22222-33333.snappy',
                'log_type_2/2017/08/26/16/test-data-11111-22222-33333.snappy',
                'log_type_3/2017/08/26/14/test-data-11111-22222-33333.snappy',
            },
            'test-bucket-with-data': {
                '2017/08/26/14/rule_name_alerts-1304134918401.json',
                '2017/07/30/14/rule_name_alerts-1304134918401.json'
            }
        })

        assert_equal(result, expected_result)

    @patch('logging.Logger.error')
    def test_get_partitions_from_keys_error(self, log_mock):
        """AthenaRefresher - Get Partitions From Keys, Bad Key"""
        bad_key = 'bad_match_string'
        result = self._refresher._get_partitions_from_keys({
            'unit-testing.streamalerts': {
                bad_key
            }
        })

        log_mock.assert_called_with('The key %s does not match any regex, skipping', bad_key)
        assert_equal(result, dict())


    @staticmethod
    def _create_test_message(count=2):
        """Helper function for creating an sqs messsage body"""
        count = min(count, 30)
        return {
            'Records': [
                {
                    's3': {
                        'bucket': {
                            'name': 'unit-testing.streamalerts'
                        },
                        'object': {
                            'key': 'alerts/dt=2017/08/{:02d}/14/02/test.json'.format(val+1)
                        }
                    }
                } for val in range(count)
            ]
        }

    @patch('logging.Logger.info')
    def test_run(self, log_mock):
        """AthenaRefresher - Run"""
        self.queue.send_message(MessageBody=json.dumps(self._create_test_message(1)))
        self._refresher.run()
        log_mock.assert_called_with('Deleted %d messages from SQS', 1)

    @patch('logging.Logger.info')
    def test_run_no_messages(self, log_mock):
        """AthenaRefresher - Run, No Messages"""
        self._refresher.run()
        log_mock.assert_called_with('No SQS messages recieved, exiting')

    @patch('logging.Logger.error')
    def test_run_invalid_bucket(self, log_mock):
        """AthenaRefresher - Run, Bad Bucket Name"""
        message = self._create_test_message(1)
        message['Records'][0]['s3']['bucket']['name'] = 'bad.bucket.name'
        self.queue.send_message(MessageBody=json.dumps(message))
        self._refresher.run()
        log_mock.assert_called_with('Failed to add hive partition(s)')

    @patch('logging.Logger.error')
    def test_run_invalid_no_records(self, log_mock):
        """AthenaRefresher - Run, No Records"""
        message = self._create_test_message(0)
        self.queue.send_message(MessageBody=json.dumps(message))
        self._refresher.run()
        log_mock.assert_called_with('No new Athena partitions to add, exiting')

    def test_run_multiple_batches(self):
        """AthenaRefresher - Run, > 20 Records"""
        message = json.dumps(self._create_test_message(1))
        for _ in range(24):
            self.queue.send_message(MessageBody=message)
        self._refresher.run()
        assert_equal(len(self._refresher._sqs_client.received_messages), 24)

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
# pylint: disable=attribute-defined-outside-init,protected-access
import json
import os
from unittest.mock import Mock, call, patch

from streamalert.athena_partitioner.main import AthenaPartitioner
from streamalert.shared.config import load_config
from tests.unit.helpers.aws_mocks import MockAthenaClient


# Without this time.sleep patch, backoff performs sleep
# operations and drastically slows down testing
@patch('time.sleep', Mock())
class TestAthenaPartitioner:
    """Test class for AthenaPartitioner when output data in Parquet format"""

    @patch('streamalert.athena_partitioner.main.load_config',
           Mock(return_value=load_config('tests/unit/conf/')))
    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    @patch('streamalert.shared.athena.boto3')
    def setup(self, boto_patch):
        """Setup the AthenaPartitioner tests"""
        boto_patch.client.return_value = MockAthenaClient()
        self._partitioner = AthenaPartitioner()

    def test_add_partitions(self):
        """AthenaPartitioner - Add Partitions"""
        self._partitioner._s3_buckets_and_keys = {
            'unit-test-streamalerts': {
                b'parquet/alerts/dt=2017-08-27-14/rule_name_alerts-1304134918401.parquet',
                b'parquet/alerts/dt=2020-02-13-08/prefix_streamalert_alert_delivery-01-abcd.parquet'
            },
            'unit-test-streamalert-data': {
                b'log_type_1/2017/08/26/14/test-data-11111-22222-33333.snappy',
                b'log_type_2/2017/08/26/14/test-data-11111-22222-33333.snappy',
                b'log_type_2/2017/08/26/15/test-data-11111-22222-33333.snappy',
                b'log_type_2/2017/08/26/16/test-data-11111-22222-33333.snappy',
                b'log_type_3/2017/08/26/14/test-data-11111-22222-33333.snappy',
                b'log_type_1/2017/08/26/11/test-data-11111-22222-33333.snappy'
            },
            'test-bucket-with-data': {
                b'dt=2020-02-12-05/log_type_1_01234.parquet',
                b'dt=2020-02-12-06/log_type_1_abcd.parquet',
                b'dt=2020-02-12-06/log_type_2_0123.parquet',
                b'dt=2020-02-12-07/log_type_2_abcd.parquet'
            }
        }
        result = self._partitioner._add_partitions()

        assert result

    @patch('logging.Logger.warning')
    def test_add_partitions_none(self, log_mock):
        """AthenaPartitioner - Add Partitions, None to Add"""
        result = self._partitioner._add_partitions()
        log_mock.assert_called_with('No partitions to add')
        assert result == False

    def test_get_partitions_from_keys_parquet(self):
        """AthenaPartitioner - Get Partitions From Keys in parquet format"""
        expected_result = {
            'alerts': {
                '(dt = \'2017-08-26-14\')': ('\'s3://unit-test-streamalerts/'
                                             'parquet/alerts/dt=2017-08-26-14\''),
                '(dt = \'2017-08-27-14\')': ('\'s3://unit-test-streamalerts/'
                                             'parquet/alerts/dt=2017-08-27-14\''),
                '(dt = \'2017-08-26-15\')': ('\'s3://unit-test-streamalerts/'
                                             'parquet/alerts/dt=2017-08-26-15\'')
            },
            'log_type_1': {
                '(dt = \'2017-08-26-14\')': ('\'s3://unit-test-streamalert-data/'
                                             'parquet/log_type_1/dt=2017-08-26-14\'')
            },
            'log_type_2': {
                '(dt = \'2017-08-26-14\')': ('\'s3://unit-test-streamalert-data/'
                                             'parquet/log_type_2/dt=2017-08-26-14\''),
                '(dt = \'2017-08-26-15\')': ('\'s3://unit-test-streamalert-data/'
                                             'parquet/log_type_2/dt=2017-08-26-15\''),
                '(dt = \'2017-08-26-16\')': ('\'s3://unit-test-streamalert-data/'
                                             'parquet/log_type_2/dt=2017-08-26-16\''),
            },
            'log_type_3': {
                '(dt = \'2017-08-26-14\')': ('\'s3://unit-test-streamalert-data/'
                                             'parquet/log_type_3/dt=2017-08-26-14\''),
            }
        }

        self._partitioner._s3_buckets_and_keys = {
            'unit-test-streamalerts': {
                b'parquet/alerts/dt=2017-08-26-14/rule_name_alerts-1304134918401.parquet',
                b'parquet/alerts/dt=2017-08-27-14/rule_name_alerts-1304134918401.parquet',
                b'parquet/alerts/dt=2017-08-26-15/rule_name_alerts-1304134918401.parquet'
            },
            'unit-test-streamalert-data': {
                b'parquet/log_type_1/dt=2017-08-26-14/test-data-11111-22222-33333.snappy',
                b'parquet/log_type_2/dt=2017-08-26-14/test-data-11111-22222-33333.snappy',
                b'parquet/log_type_2/dt=2017-08-26-14/test-data-11111-22222-33334.snappy',
                b'parquet/log_type_2/dt=2017-08-26-15/test-data-11111-22222-33333.snappy',
                b'parquet/log_type_2/dt=2017-08-26-16/test-data-11111-22222-33333.snappy',
                b'parquet/log_type_3/dt=2017-08-26-14/test-data-11111-22222-33333.snappy',
            },
            'test-bucket-with-data': {
                b'dt=2017-08-26-14/rule_name_alerts-1304134918401.parquet',
                b'dt=2017-07-30-14/rule_name_alerts-1304134918401.parquet'
            }
        }

        result = self._partitioner._get_partitions_from_keys()

        assert result == expected_result

    @patch('logging.Logger.warning')
    def test_get_partitions_from_keys_error(self, log_mock):
        """AthenaPartitioner - Get Partitions From Keys, Bad Key"""
        bad_key = b'bad_match_string'
        self._partitioner._s3_buckets_and_keys = {
            'unit-test-streamalerts': {
                bad_key
            }
        }

        result = self._partitioner._get_partitions_from_keys()

        log_mock.assert_called_with('The key %s does not match any regex, skipping',
                                    bad_key.decode('utf-8'))
        assert result == {}

    @staticmethod
    def _s3_record(count):
        return {
            'Records': [
                {
                    's3': {
                        'bucket': {
                            'name': 'unit-test-streamalerts'
                        },
                        'object': {
                            'key': ('parquet/alerts/dt=2017-08-{:02d}-'
                                    '14/02/test.json'.format(val + 1))
                        }
                    }
                } for val in range(count)
            ]
        }

    @staticmethod
    def _s3_record_placeholder_file():
        return {
            'Records': [
                {
                    's3': {
                        'bucket': {
                            'name': 'unit-test-streamalerts'
                        },
                        'object': {
                            'key': 'parquet/alerts/dt=2017-08-01-14/02/test.json_$folder$'
                        }
                    }
                }
            ]
        }

    @staticmethod
    def _create_test_message(count=2, placeholder=False):
        """Helper function for creating an sqs messsage body"""
        if placeholder:
            body = json.dumps(TestAthenaPartitioner._s3_record_placeholder_file())
        else:
            count = min(count, 30)
            body = json.dumps(TestAthenaPartitioner._s3_record(count))
        return {
            'Records': [
                {
                    'body': body,
                    'messageId': "40d4fac0-64a1-4a20-8be4-893c51aebca1",
                    "attributes": {
                        "SentTimestamp": "1534284301036"
                    }
                }
            ]
        }

    @patch('logging.Logger.debug')
    @patch('streamalert.athena_partitioner.main.AthenaPartitioner._add_partitions')
    def test_run(self, add_mock, log_mock):
        """AthenaPartitioner - Run"""
        add_mock.return_value = True
        self._partitioner.run(self._create_test_message(1))
        log_mock.assert_called_with(
            'Received notification for object \'%s\' in bucket \'%s\'',
            b'parquet/alerts/dt=2017-08-01-14/02/test.json',
            'unit-test-streamalerts'
        )

    @patch('logging.Logger.info')
    def test_run_placeholder_file(self, log_mock):
        """AthenaPartitioner - Run, Placeholder File"""
        self._partitioner.run(self._create_test_message(1, True))
        log_mock.assert_has_calls([
            call(
                'Skipping placeholder file notification with key: %s',
                b'parquet/alerts/dt=2017-08-01-14/02/test.json_$folder$'
            )
        ])

    @patch('logging.Logger.warning')
    def test_run_no_messages(self, log_mock):
        """AthenaPartitioner - Run, No Messages"""
        self._partitioner.run(self._create_test_message(0))
        log_mock.assert_called_with('No partitions to add')

    @patch('logging.Logger.error')
    def test_run_invalid_bucket(self, log_mock):
        """AthenaPartitioner - Run, Bad Bucket Name"""
        event = self._create_test_message(0)
        bucket = 'bad.bucket.name'
        s3_record = self._s3_record(1)
        s3_record['Records'][0]['s3']['bucket']['name'] = bucket
        event['Records'][0]['body'] = json.dumps(s3_record)
        self._partitioner.run(event)
        log_mock.assert_called_with('\'%s\' not found in \'buckets\' config. Please add this '
                                    'bucket to enable additions of Hive partitions.',
                                    bucket)


@patch('time.sleep', Mock())
class TestAthenaPartitionerJSON:
    """Test class for AthenaPartitioner when output data in JSON format"""

    @patch('streamalert.athena_partitioner.main.load_config',
           Mock(return_value=load_config('tests/unit/conf_athena/')))
    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    @patch('streamalert.shared.athena.boto3')
    def setup(self, boto_patch):
        """Setup the AthenaPartitioner tests"""
        boto_patch.client.return_value = MockAthenaClient()
        self._partitioner = AthenaPartitioner()

    def test_get_partitions_from_keys_json(self):
        """AthenaPartitioner - Get Partitions From Keys in json format"""
        expected_result = {
            'alerts': {
                '(dt = \'2017-08-26-14\')': ('\'s3://unit-test-streamalerts/'
                                             'parquet/alerts/dt=2017-08-26-14\''),
                '(dt = \'2017-08-27-14\')': ('\'s3://unit-test-streamalerts/'
                                             'parquet/alerts/dt=2017-08-27-14\''),
                '(dt = \'2017-08-26-15\')': ('\'s3://unit-test-streamalerts/'
                                             'alerts/2017/08/26/15\'')
            },
            'log_type_1': {
                '(dt = \'2017-08-26-14\')': ('\'s3://unit-test-streamalert-data/'
                                             'log_type_1/2017/08/26/14\'')
            },
            'log_type_2': {
                '(dt = \'2017-08-26-14\')': ('\'s3://unit-test-streamalert-data/'
                                             'log_type_2/2017/08/26/14\''),
                '(dt = \'2017-08-26-15\')': ('\'s3://unit-test-streamalert-data/'
                                             'log_type_2/2017/08/26/15\''),
                '(dt = \'2017-08-26-16\')': ('\'s3://unit-test-streamalert-data/'
                                             'log_type_2/2017/08/26/16\''),
            },
            'log_type_3': {
                '(dt = \'2017-08-26-14\')': ('\'s3://unit-test-streamalert-data/'
                                             'log_type_3/2017/08/26/14\''),
            }
        }

        self._partitioner._s3_buckets_and_keys = {
            'unit-test-streamalerts': {
                b'parquet/alerts/dt=2017-08-26-14/rule_name_alerts-1304134918401.json',
                b'parquet/alerts/dt=2017-08-27-14/rule_name_alerts-1304134918401.json',
                b'alerts/2017/08/26/15/rule_name_alerts-1304134918401.json'
            },
            'unit-test-streamalert-data': {
                b'log_type_1/2017/08/26/14/test-data-11111-22222-33333.snappy',
                b'log_type_2/2017/08/26/14/test-data-11111-22222-33333.snappy',
                b'log_type_2/2017/08/26/14/test-data-11111-22222-33334.snappy',
                b'log_type_2/2017/08/26/15/test-data-11111-22222-33333.snappy',
                b'log_type_2/2017/08/26/16/test-data-11111-22222-33333.snappy',
                b'log_type_3/2017/08/26/14/test-data-11111-22222-33333.snappy',
            },
            'test-bucket-with-data': {
                b'2017/08/26/14/rule_name_alerts-1304134918401.json',
                b'2017/07/30/14/rule_name_alerts-1304134918401.json'
            }
        }

        result = self._partitioner._get_partitions_from_keys()

        assert result == expected_result

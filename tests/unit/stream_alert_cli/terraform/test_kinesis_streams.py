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
from nose.tools import assert_equal, assert_true

from stream_alert_cli.config import CLIConfig
from stream_alert_cli.terraform import _common, kinesis_streams

CONFIG = CLIConfig(config_path='tests/unit/conf')


def test_kinesis_streams():
    """CLI - Terraform Generate Kinesis Streams"""
    cluster_dict = _common.infinitedict()
    result = kinesis_streams.generate_kinesis_streams('advanced',
                                                      cluster_dict,
                                                      CONFIG)

    expected_result = {
        'module': {
            'kinesis_advanced': {
                'source': 'modules/tf_stream_alert_kinesis_streams',
                'account_id': '12345678910',
                'shard_level_metrics': ["IncomingBytes"],
                'region': 'us-west-1',
                'prefix': 'unit-testing',
                'cluster_name': 'advanced',
                'stream_name': 'unit-testing_advanced_stream_alert_kinesis',
                'shards': 1,
                'retention': 24,
                'create_user': True,
                'trusted_accounts': []
            }
        }
    }

    assert_true(result)
    assert_equal(cluster_dict, expected_result)


def test_kinesis_streams_with_trusted_account():
    """CLI - Terraform Generate Kinesis Streams with trusted account"""
    cluster_dict = _common.infinitedict()
    result = kinesis_streams.generate_kinesis_streams('trusted',
                                                      cluster_dict,
                                                      CONFIG)

    expected_result = {
        'module': {
            'kinesis_trusted': {
                'source': 'modules/tf_stream_alert_kinesis_streams',
                'account_id': '12345678910',
                'shard_level_metrics': [],
                'region': 'us-west-1',
                'prefix': 'unit-testing',
                'cluster_name': 'trusted',
                'stream_name': 'unit-testing_trusted_stream_alert_kinesis',
                'shards': 1,
                'retention': 24,
                'create_user': True,
                'trusted_accounts': [
                    '98765432100'
                ]
            }
        }
    }

    assert_true(result)
    assert_equal(cluster_dict, expected_result)

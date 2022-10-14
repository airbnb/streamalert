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

from streamalert_cli.config import CLIConfig
from streamalert_cli.terraform import common, kinesis_streams

CONFIG = CLIConfig(config_path='tests/unit/conf')


def test_kinesis_streams():
    """CLI - Terraform Generate Kinesis Streams"""
    cluster_dict = common.infinitedict()
    result = kinesis_streams.generate_kinesis_streams(
        'advanced',
        cluster_dict,
        CONFIG
    )

    expected_result = {
        'module': {
            'kinesis_advanced': {
                'source': './modules/tf_kinesis_streams',
                'account_id': '12345678910',
                'shard_level_metrics': ["IncomingBytes"],
                'region': 'us-west-1',
                'prefix': 'unit-test',
                'cluster': 'advanced',
                'stream_name': 'unit-test_advanced_streamalert',
                'shards': 1,
                'retention': 24,
                'create_user': True,
                'trusted_accounts': []
            }
        },
        'output': {
            'kinesis_advanced_access_key_id': {
                'value': '${module.kinesis_advanced.access_key_id}',
                'sensitive': 'true'
            },
            'kinesis_advanced_secret_key': {
                'value': '${module.kinesis_advanced.secret_key}',
                'sensitive': 'true'
            },
            'kinesis_advanced_user_arn': {
                'value': '${module.kinesis_advanced.user_arn}',
                'sensitive': 'true'
            }
        }
    }

    assert result
    assert cluster_dict == expected_result


def test_kinesis_streams_with_trusted_account():
    """CLI - Terraform Generate Kinesis Streams with trusted account"""
    cluster_dict = common.infinitedict()
    result = kinesis_streams.generate_kinesis_streams(
        'trusted',
        cluster_dict,
        CONFIG
    )

    expected_result = {
        'module': {
            'kinesis_trusted': {
                'source': './modules/tf_kinesis_streams',
                'account_id': '12345678910',
                'shard_level_metrics': [],
                'region': 'us-west-1',
                'prefix': 'unit-test',
                'cluster': 'trusted',
                'stream_name': 'unit-test_trusted_streamalert',
                'shards': 1,
                'retention': 24,
                'create_user': True,
                'trusted_accounts': [
                    '98765432100'
                ]
            }
        },
        'output': {
            'kinesis_trusted_access_key_id': {
                'value': '${module.kinesis_trusted.access_key_id}',
                'sensitive': 'true'
            },
            'kinesis_trusted_secret_key': {
                'value': '${module.kinesis_trusted.secret_key}',
                'sensitive': 'true'
            },
            'kinesis_trusted_username': {
                'value': '${module.kinesis_trusted.username}',
                'sensitive': 'true'
            }
        }
    }

    assert result
    assert cluster_dict == expected_result


def test_kinesis_streams_with_custom_name():
    """CLI - Terraform Generate Kinesis Streams with Custom Name"""
    cluster_dict = common.infinitedict()
    stream_name = 'test-stream-name'
    cluster = 'advanced'
    CONFIG['clusters'][cluster]['modules']['kinesis']['streams']['stream_name'] = stream_name
    result = kinesis_streams.generate_kinesis_streams(
        cluster,
        cluster_dict,
        CONFIG
    )

    expected_result = {
        'module': {
            'kinesis_advanced': {
                'source': './modules/tf_kinesis_streams',
                'account_id': '12345678910',
                'shard_level_metrics': ["IncomingBytes"],
                'region': 'us-west-1',
                'prefix': 'unit-test',
                'cluster': cluster,
                'stream_name': stream_name,
                'shards': 1,
                'retention': 24,
                'create_user': True,
                'trusted_accounts': []
            }
        },
        'output': {
            'kinesis_advanced_access_key_id': {
                'value': '${module.kinesis_advanced.access_key_id}',
                'sensitive': 'true'
            },
            'kinesis_advanced_secret_key': {
                'value': '${module.kinesis_advanced.secret_key}',
                'sensitive': 'true'
            },
            'kinesis_advanced_user_arn': {
                'value': '${module.kinesis_advanced.user_arn}',
                'sensitive': 'true'
            }
        }
    }

    assert result
    assert cluster_dict == expected_result

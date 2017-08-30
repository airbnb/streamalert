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
from nose.tools import assert_equal

from stream_alert_cli.config import CLIConfig
from stream_alert_cli.terraform import athena

CONFIG = CLIConfig(config_path='tests/unit/conf')

def test_generate_athena():
    """CLI - Terraform Generate Athena"""

    CONFIG['lambda']['athena_partition_refresh_config'] = {
        'enabled': True,
        'current_version': '$LATEST',
        'refresh_type': {
            'repair_hive_table': {
                'unit-testing.streamalerts': 'alerts'
            },
            'add_hive_partition': {
                'unit-testing-2.streamalerts': 'alerts'
            }
        },
        'handler': 'main.handler',
        'timeout': '60',
        'memory': '128',
        'source_bucket': 'unit-testing.streamalert.source',
        'source_current_hash': '12345',
        'source_object_key': 'lambda/athena/source.zip',
        'third_party_libraries': [
            'backoff'
        ]
    }
    expected_athena_config = {
        'module': {
            'stream_alert_athena': {
                'source': 'modules/tf_stream_alert_athena',
                'current_version': '$LATEST',
                'enable_metrics': False,
                'lambda_handler': 'main.handler',
                'lambda_log_level': 'info',
                'lambda_memory': '128',
                'lambda_timeout': '60',
                'lambda_s3_bucket': 'unit-testing.streamalert.source',
                'lambda_s3_key': 'lambda/athena/source.zip',
                'athena_data_buckets': [
                    'unit-testing.streamalerts',
                    'unit-testing-2.streamalerts'
                ],
                'prefix': 'unit-testing',
                'refresh_interval': 'rate(10 minutes)'
            },
            'athena_monitoring': {
                'source': 'modules/tf_stream_alert_monitoring',
                'sns_topic_arn': 'arn:aws:sns:us-west-1:12345678910:stream_alert_monitoring',
                'kinesis_alarms_enabled': False,
                'lambda_functions': ['unit-testing_streamalert_athena_partition_refresh']
            },
            'athena_metric_filters': []
        }
    }

    athena_config = athena.generate_athena(config=CONFIG)

    # List order messes up the comparison between both dictionaries
    assert_equal(set(athena_config['module']['stream_alert_athena']['athena_data_buckets']),
                 set(expected_athena_config['module']['stream_alert_athena']\
                                           ['athena_data_buckets']))

    # Delete the keys to compare the rest of the generated module
    del athena_config['module']['stream_alert_athena']['athena_data_buckets']
    del expected_athena_config['module']['stream_alert_athena']['athena_data_buckets']

    # Compare each generated Athena module from the expected module
    assert_equal(athena_config['module']['stream_alert_athena'],
                 expected_athena_config['module']['stream_alert_athena'])
    assert_equal(athena_config['module']['athena_monitoring'],
                 expected_athena_config['module']['athena_monitoring'])

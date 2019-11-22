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

from streamalert_cli.config import CLIConfig
from streamalert_cli.terraform import athena

CONFIG = CLIConfig(config_path='tests/unit/conf')

def test_generate_athena():
    """CLI - Terraform Generate Athena"""

    CONFIG['lambda']['athena_partition_refresh_config'] = {
        'buckets': {
            'unit-test.streamalerts': 'alerts',
            'unit-test.streamalert.data': 'data'
        },
        'timeout': '60',
        'memory': '128',
        'third_party_libraries': []
    }

    prefix = CONFIG['global']['account']['prefix']

    expected_athena_config = {
        'module': {
            'stream_alert_athena': {
                's3_logging_bucket': '{}.streamalert.s3-logging'.format(prefix),
                'source': './modules/tf_athena',
                'database_name': '{}_streamalert'.format(prefix),
                'queue_name': '{}_streamalert_athena_s3_notifications'.format(prefix),
                'results_bucket': '{}.streamalert.athena-results'.format(prefix),
                'kms_key_id': '${aws_kms_key.server_side_encryption.key_id}',
                'lambda_handler': 'streamalert.athena_partition_refresh.main.handler',
                'lambda_log_level': 'info',
                'lambda_memory': '128',
                'lambda_timeout': '60',
                'athena_data_buckets': [
                    'unit-test.streamalerts',
                    'unit-test.streamalert.data'
                ],
                'prefix': 'unit-test',
                'account_id': '12345678910',
                'concurrency_limit': 10
            },
            'athena_monitoring': {
                'source': './modules/tf_monitoring',
                'sns_topic_arn': (
                    'arn:aws:sns:us-west-1:12345678910:unit-test_streamalert_monitoring'
                ),
                'kinesis_alarms_enabled': False,
                'lambda_functions': ['unit-test_streamalert_athena_partition_refresh']
            },
            'athena_metric_filters': []
        }
    }

    athena_config = athena.generate_athena(config=CONFIG)

    # List order messes up the comparison between both dictionaries
    assert_equal(
        set(athena_config['module']['stream_alert_athena']['athena_data_buckets']),
        set(expected_athena_config['module']['stream_alert_athena']['athena_data_buckets'])
    )

    # Delete the keys to compare the rest of the generated module
    del athena_config['module']['stream_alert_athena']['athena_data_buckets']
    del expected_athena_config['module']['stream_alert_athena']['athena_data_buckets']

    # Compare each generated Athena module from the expected module
    assert_equal(athena_config['module']['stream_alert_athena'],
                 expected_athena_config['module']['stream_alert_athena'])
    assert_equal(athena_config['module']['athena_monitoring'],
                 expected_athena_config['module']['athena_monitoring'])

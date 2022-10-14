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
from streamalert_cli.terraform import scheduled_queries

CONFIG = CLIConfig(config_path='tests/unit/conf')


def test_generate_scheduled_queries():
    """CLI - Terraform Generate Scheduled Queries"""

    expected_sq_config = {
        'module': {
            'scheduled_queries': {
                'source': './modules/tf_scheduled_queries',
                'destination_kinesis_stream': 'unit-test_stream',
                'sfn_timeout_secs': 3600,
                'sfn_wait_secs': 30,
                'prefix': 'unit-test',
                'account_id': '12345678910',
                'region': 'us-west-1',
                'athena_database': 'unit-test_streamalert',
                'athena_results_bucket': 'unit-test-streamalert-athena-results',
                'athena_s3_buckets': [
                    '${aws_s3_bucket.streamalerts.bucket}',
                    '${module.kinesis_firehose_setup.data_bucket_name}',
                    'bucket',
                ],
                'lambda_handler': 'streamalert.scheduled_queries.main.handler',
                'query_packs': [
                    {
                        'name': 'hourly',
                        'schedule_expression': 'cron(5 * * * ? *)',
                        'description': 'Runs all hourly queries. Once per day on :05'
                    }
                ],
                'lambda_log_level': 'info',
                'lambda_memory': 128,
                'lambda_timeout': 60,
                'lambda_log_retention_days': 14,
                'lambda_alarms_enabled': True,
                'lambda_error_threshold': 1,
                'lambda_error_period_secs': 3600,
                'lambda_error_evaluation_periods': 2,
                'lambda_alarm_actions': [
                    'arn:aws:sns:us-west-1:12345678910:unit-test_streamalert_monitoring'
                ],
            }
        }
    }

    result = scheduled_queries.generate_scheduled_queries_module_configuration(CONFIG)

    assert result == expected_sq_config

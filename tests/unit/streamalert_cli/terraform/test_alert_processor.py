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
import unittest

from streamalert_cli.config import CLIConfig
from streamalert_cli.terraform import alert_processor


class TestAlertProcessor(unittest.TestCase):
    """Test the Terraform generation for the alert processor"""

    def setUp(self):
        """Create the CLIConfig and the expected template for these tests."""
        self.config = dict(CLIConfig(config_path='tests/unit/conf'))
        self.alert_proc_config = self.config['lambda']['alert_processor_config']

    def test_generate_all_options(self):
        """CLI - Terraform Generate Alert Processor - All Options"""
        result = alert_processor.generate_alert_processor(config=self.config)
        expected = {
            'module': {
                'alert_processor_iam': {
                    'account_id': '12345678910',
                    'kms_key_arn': '${aws_kms_key.streamalert_secrets.arn}',
                    'output_lambda_functions':
                    ['unit_test_function', 'unit_test_qualified_function'],
                    'output_s3_buckets': ['unit.test.bucket.name'],
                    'output_sns_topics': ['unit_test_topic_name'],
                    'output_sqs_queues': ['unit_test_queue_name'],
                    'prefix': 'unit-test',
                    'region': 'us-west-1',
                    'role_id': '${module.alert_processor_lambda.role_id}',
                    'source': './modules/tf_alert_processor_iam',
                    'sse_kms_key_arn': '${aws_kms_key.server_side_encryption.arn}'
                },
                'alert_processor_lambda': {
                    'alarm_actions':
                    ['arn:aws:sns:us-west-1:12345678910:unit-test_streamalert_monitoring'],
                    'description':
                    'Unit-Test Streamalert Alert Processor',
                    'environment_variables': {
                        'ALERTS_TABLE': 'unit-test_streamalert_alerts',
                        'STREAMALERT_PREFIX': 'unit-test',
                        'AWS_ACCOUNT_ID': '12345678910',
                        'ENABLE_METRICS': '0',
                        'LOGGER_LEVEL': 'info'
                    },
                    'tags': {},
                    'errors_alarm_enabled':
                    True,
                    'errors_alarm_evaluation_periods':
                    1,
                    'errors_alarm_period_secs':
                    2,
                    'errors_alarm_threshold':
                    3,
                    'function_name':
                    'unit-test_streamalert_alert_processor',
                    'handler':
                    'streamalert.alert_processor.main.handler',
                    'log_retention_days':
                    7,
                    'memory_size_mb':
                    128,
                    'source':
                    './modules/tf_lambda',
                    'throttles_alarm_enabled':
                    True,
                    'throttles_alarm_evaluation_periods':
                    4,
                    'throttles_alarm_period_secs':
                    5,
                    'throttles_alarm_threshold':
                    6,
                    'timeout_sec':
                    60,
                    'vpc_security_group_ids': ['sg-abc'],
                    'vpc_subnet_ids': ['subnet-123']
                }
            }
        }
        assert expected == result

    def test_generate_minimal_options(self):
        """CLI - Terraform Generate Alert Processor - Minimal Options"""
        # Remove extra Lambda options
        for key in ['log_level', 'log_retention_days', 'metric_alarms', 'vpc_config']:
            del self.alert_proc_config[key]

        # Remove all outputs from the config
        self.config['outputs'] = {}

        result = alert_processor.generate_alert_processor(config=self.config)

        expected = {
            'module': {
                'alert_processor_iam': {
                    'account_id': '12345678910',
                    'kms_key_arn': '${aws_kms_key.streamalert_secrets.arn}',
                    'output_lambda_functions': [],
                    'output_s3_buckets': [],
                    'output_sns_topics': [],
                    'output_sqs_queues': [],
                    'prefix': 'unit-test',
                    'region': 'us-west-1',
                    'role_id': '${module.alert_processor_lambda.role_id}',
                    'source': './modules/tf_alert_processor_iam',
                    'sse_kms_key_arn': '${aws_kms_key.server_side_encryption.arn}'
                },
                'alert_processor_lambda': {
                    'description': 'Unit-Test Streamalert Alert Processor',
                    'environment_variables': {
                        'ALERTS_TABLE': 'unit-test_streamalert_alerts',
                        'STREAMALERT_PREFIX': 'unit-test',
                        'AWS_ACCOUNT_ID': '12345678910',
                        'ENABLE_METRICS': '0',
                        'LOGGER_LEVEL': 'info'
                    },
                    'tags': {},
                    'function_name': 'unit-test_streamalert_alert_processor',
                    'handler': 'streamalert.alert_processor.main.handler',
                    'memory_size_mb': 128,
                    'source': './modules/tf_lambda',
                    'timeout_sec': 60,
                }
            }
        }
        assert expected == result

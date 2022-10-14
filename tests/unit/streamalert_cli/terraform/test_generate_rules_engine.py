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

from streamalert_cli.terraform import rules_engine


class TestTerraformGenerateRuleEngine:
    """CLI Terraform Generate, Rules Engine"""
    # pylint: disable=no-self-use,attribute-defined-outside-init

    def setup(self):
        """CLI Terraform Generate, Rules Engine - Setup"""
        self.config = {
            'global': {
                'account': {
                    'aws_account_id': '123456789012',
                    'prefix': 'unit-test',
                    'region': 'us-east-1'
                },
                'infrastructure': {
                    'monitoring': {
                        'sns_topic_name': 'test_topic'
                    },
                    'rule_staging': {
                        'enabled': False
                    }
                }
            },
            'threat_intel': {
                'dynamodb_table_name': 'test_table',
                'enabled': False
            },
            'lambda': {
                'rules_engine_config': {
                    'log_level': 'info',
                    'log_retention_days': 14,
                    'memory': 128,
                    'metric_alarms': {
                        'errors': {
                            'enabled': True,
                            'evaluation_periods': 1,
                            'period_secs': 120,
                            'threshold': 0
                        },
                        'throttles': {
                            'enabled': True,
                            'evaluation_periods': 1,
                            'period_secs': 120,
                            'threshold': 0
                        }
                    },
                    'timeout': 60,
                    'vpc_config': {
                        'security_group_ids': [],
                        'subnet_ids': []
                    }
                }
            }
        }

    def test_generate_rules_engine(self):
        """CLI - Terraform Generate, Rules Engine"""
        result = rules_engine.generate_rules_engine(self.config)

        expected_result = {
            'module': {
                'rules_engine_iam': {
                    'source': './modules/tf_rules_engine',
                    'account_id': '123456789012',
                    'region': 'us-east-1',
                    'prefix': 'unit-test',
                    'function_alias_arn': '${module.rules_engine_lambda.function_alias_arn}',
                    'function_name': '${module.rules_engine_lambda.function_name}',
                    'function_role_id': '${module.rules_engine_lambda.role_id}',
                    'threat_intel_enabled': self.config['threat_intel']['enabled'],
                    'dynamodb_table_name': self.config['threat_intel']['dynamodb_table_name'],
                    'rules_table_arn': '${module.globals.rules_table_arn}',
                    'enable_rule_staging': False,
                    'classifier_sqs_queue_arn': '${module.globals.classifier_sqs_queue_arn}',
                    'classifier_sqs_sse_kms_key_arn': (
                        '${module.globals.classifier_sqs_sse_kms_key_arn}'
                    ),
                    'sqs_record_batch_size': 10
                },
                'rules_engine_lambda': {
                    'alarm_actions': ['arn:aws:sns:us-east-1:123456789012:test_topic'],
                    'description': 'Unit-Test Streamalert Rules Engine',
                    'environment_variables': {
                        'ALERTS_TABLE': 'unit-test_streamalert_alerts',
                        'ENABLE_METRICS': '0',
                        'LOGGER_LEVEL': 'info',
                        'STREAMALERT_PREFIX': 'unit-test',
                    },
                    'tags': {},
                    'errors_alarm_enabled': True,
                    'errors_alarm_evaluation_periods': 1,
                    'errors_alarm_period_secs': 120,
                    'errors_alarm_threshold': 0,
                    'function_name': 'unit-test_streamalert_rules_engine',
                    'handler': 'streamalert.rules_engine.main.handler',
                    'log_retention_days': 14,
                    'memory_size_mb': 128,
                    'source': './modules/tf_lambda',
                    'throttles_alarm_enabled': True,
                    'throttles_alarm_evaluation_periods': 1,
                    'throttles_alarm_period_secs': 120,
                    'throttles_alarm_threshold': 0,
                    'timeout_sec': 60,
                    'vpc_security_group_ids': [],
                    'vpc_subnet_ids': []
                }
            }
        }

        assert result == expected_result

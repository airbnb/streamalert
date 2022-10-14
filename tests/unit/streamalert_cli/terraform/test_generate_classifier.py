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

from streamalert_cli.terraform import classifier, common


class TestTerraformGenerateClassifier:
    """CLI Terraform Generate, Classifier"""
    # pylint: disable=no-self-use,attribute-defined-outside-init

    def setup(self):
        """CLI Terraform Generate, Classifier - Setup"""
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
                    }
                }
            },
            'clusters': {
                'test': {
                    'classifier_config': {
                        'inputs': {
                            'aws-sns': [
                                'arn:aws:sns:us-east-1:123456789012:foo_bar'
                            ]
                        },
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
        }

    def test_generate_classifier(self):
        """CLI - Terraform Generate, Classifier"""
        cluster_dict = common.infinitedict()
        classifier.generate_classifier(
            'test',
            cluster_dict,
            self.config
        )

        expected_result = {
            'module': {
                'classifier_test_iam': {
                    'source': './modules/tf_classifier',
                    'account_id': '123456789012',
                    'region': 'us-east-1',
                    'prefix': 'unit-test',
                    'firehose_use_prefix': True,
                    'function_role_id': '${module.classifier_test_lambda.role_id}',
                    'function_alias_arn': '${module.classifier_test_lambda.function_alias_arn}',
                    'function_name': '${module.classifier_test_lambda.function_name}',
                    'classifier_sqs_queue_arn': '${module.globals.classifier_sqs_queue_arn}',
                    'classifier_sqs_sse_kms_key_arn': (
                        '${module.globals.classifier_sqs_sse_kms_key_arn}'
                    ),
                    'input_sns_topics': [
                        'arn:aws:sns:us-east-1:123456789012:foo_bar'
                    ]
                },
                'classifier_test_lambda': {
                    'alarm_actions': ['arn:aws:sns:us-east-1:123456789012:test_topic'],
                    'description': 'Unit-Test Test Streamalert Classifier',
                    'environment_variables': {
                        'CLUSTER': 'test',
                        'SQS_QUEUE_URL': '${module.globals.classifier_sqs_queue_url}',
                        'LOGGER_LEVEL': 'info',
                        'ENABLE_METRICS': '0'
                    },
                    'tags': {
                        'Cluster': 'test'
                    },
                    'errors_alarm_enabled': True,
                    'errors_alarm_evaluation_periods': 1,
                    'errors_alarm_period_secs': 120,
                    'errors_alarm_threshold': 0,
                    'function_name': 'unit-test_test_streamalert_classifier',
                    'handler': 'streamalert.classifier.main.handler',
                    'log_retention_days': 14,
                    'memory_size_mb': 128,
                    'source': './modules/tf_lambda',
                    'throttles_alarm_enabled': True,
                    'throttles_alarm_evaluation_periods': 1,
                    'throttles_alarm_period_secs': 120,
                    'throttles_alarm_threshold': 0,
                    'timeout_sec': 60,
                    'vpc_security_group_ids': [],
                    'vpc_subnet_ids': [],
                    'input_sns_topics': [
                        'arn:aws:sns:us-east-1:123456789012:foo_bar'
                    ]
                }
            }
        }

        assert cluster_dict == expected_result

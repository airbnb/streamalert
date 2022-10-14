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
from streamalert_cli.terraform import rule_promotion


class TestRulePromotion:
    """Test the Terraform generation for the rule promotion function"""

    def setup(self):
        """Create the CLIConfig and the expected template for these tests."""
        # pylint: disable=attribute-defined-outside-init
        self.config = dict(CLIConfig(config_path='tests/unit/conf'))
        self.rule_promo_config = self.config['lambda']['rule_promotion_config']

    def test_generate(self):
        """CLI - Terraform Generate Rule Promotion, Staging Enabled"""
        self.config['global']['infrastructure']['rule_staging']['enabled'] = True
        result = rule_promotion.generate_rule_promotion(config=self.config)
        expected = {
            'module': {
                'rule_promotion_iam': {
                    'role_id': '${module.rule_promotion_lambda.role_id}',
                    'function_alias_arn': '${module.rule_promotion_lambda.function_alias_arn}',
                    'function_name': '${module.rule_promotion_lambda.function_name}',
                    'rules_table_arn': '${module.globals.rules_table_arn}',
                    'source': './modules/tf_rule_promotion_iam',
                    'send_digest_schedule_expression': 'cron(30 13 * * ? *)',
                    'digest_sns_topic': 'unit-test_streamalert_rule_staging_stats',
                    'athena_results_bucket_arn': (
                        '${module.athena_partitioner_iam.results_bucket_arn}'
                    ),
                    'alerts_bucket': 'unit-test-streamalerts',
                    's3_kms_key_arn': '${aws_kms_key.server_side_encryption.arn}'
                },
                'rule_promotion_lambda': {
                    'alarm_actions': [
                        'arn:aws:sns:us-west-1:12345678910:unit-test_streamalert_monitoring'
                    ],
                    'description': 'Unit-Test Streamalert Rule Promotion',
                    'environment_variables': {
                        'ENABLE_METRICS': '0',
                        'LOGGER_LEVEL': 'info'
                    },
                    'tags': {},
                    'errors_alarm_enabled': True,
                    'errors_alarm_evaluation_periods': 1,
                    'errors_alarm_period_secs': 2,
                    'errors_alarm_threshold': 3,
                    'function_name': 'unit-test_streamalert_rule_promotion',
                    'handler': 'streamalert.rule_promotion.main.handler',
                    'log_retention_days': 10,
                    'memory_size_mb': 128,
                    'source': './modules/tf_lambda',
                    'throttles_alarm_enabled': True,
                    'throttles_alarm_evaluation_periods': 4,
                    'throttles_alarm_period_secs': 5,
                    'throttles_alarm_threshold': 6,
                    'timeout_sec': 120,
                    'schedule_expression': 'rate(10 minutes)'
                }
            }
        }

        assert result == expected

    def test_generate_disabled(self):
        """CLI - Terraform Generate Rule Promotion, Staging Disabled"""
        result = rule_promotion.generate_rule_promotion(config=self.config)
        assert result == False

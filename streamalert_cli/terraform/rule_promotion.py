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
from streamalert.rule_promotion.publisher import StatsPublisher
from streamalert.shared import RULE_PROMOTION_NAME
from streamalert_cli.manage_lambda.package import RulePromotionPackage
from streamalert_cli.terraform.common import infinitedict
from streamalert_cli.terraform.lambda_module import generate_lambda


def generate_rule_promotion(config):
    """Generate Terraform for the Rule Promotion function

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        dict: Rule Promotion dict to be marshaled to JSON
    """
    # The Rule Promotion Lambda function is dependent on the rule staging feature being
    # enabled, so do not generate the code for this Lambda function if it not enabled
    if not config['global']['infrastructure']['rule_staging'].get('enabled', False):
        return False

    result = infinitedict()

    athena_config = config['lambda']['athena_partition_refresh_config']
    data_buckets = sorted(athena_config['buckets'])

    # Set variables for the IAM permissions, etc module
    result['module']['rule_promotion_iam'] = {
        'source': './modules/tf_rule_promotion_iam',
        'send_digest_schedule_expression':
            config['lambda']['rule_promotion_config']['send_digest_schedule_expression'],
        'digest_sns_topic': StatsPublisher.formatted_sns_topic_arn(config).split(':')[-1],
        'role_id': '${module.rule_promotion_lambda.role_id}',
        'rules_table_arn': '${module.globals.rules_table_arn}',
        'function_alias_arn': '${module.rule_promotion_lambda.function_alias_arn}',
        'function_name': '${module.rule_promotion_lambda.function_name}',
        'athena_results_bucket_arn': '${module.stream_alert_athena.results_bucket_arn}',
        'athena_data_buckets': data_buckets,
        's3_kms_key_arn': '${aws_kms_key.server_side_encryption.arn}'
    }

    # Set variables for the Lambda module
    result['module']['rule_promotion_lambda'] = generate_lambda(
        '{}_streamalert_{}'.format(config['global']['account']['prefix'], RULE_PROMOTION_NAME),
        RulePromotionPackage.package_name + '.zip',
        RulePromotionPackage.lambda_handler,
        config['lambda']['rule_promotion_config'],
        config
    )

    return result

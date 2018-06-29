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
import json

from stream_alert.rule_promotion.publisher import StatsPublisher
from stream_alert.shared import RULE_PROMOTION_NAME
from stream_alert_cli.manage_lambda.package import RulePromotionPackage
from stream_alert_cli.terraform.common import infinitedict
from stream_alert_cli.terraform.lambda_module import generate_lambda


def generate_rule_promotion(config):
    """Generate Terraform for the Rule Promotion function

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        dict: Rule Promotion dict to be marshaled to JSON
    """
    result = infinitedict()

    state_param = json.dumps({
        'send_digest_hour_utc':
            int(config['lambda']['rule_promotion_config']['send_digest_hour_utc']),
        'sent_daily_digest': False
    }, sort_keys=True)

    # Set variables for the IAM permissions, etc module
    result['module']['rule_promotion_iam'] = {
        'source': 'modules/tf_rule_promotion_iam',
        'stats_publisher_state_name': StatsPublisher.SSM_STATE_NAME,
        'stats_publisher_state_value': state_param,
        'digest_sns_topic': StatsPublisher.formatted_sns_topic_arn(config).split(':')[-1],
        'role_id': '${module.rule_promotion_lambda.role_id}',
        'rules_table_arn': '${module.globals.rules_table_arn}'
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

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
from streamalert.shared import RULES_ENGINE_FUNCTION_NAME
from streamalert_cli.terraform.common import infinitedict
from streamalert_cli.terraform.lambda_module import generate_lambda


def generate_rules_engine(config):
    """Generate Terraform for the Rules Engine
    Args:
        config (dict): The loaded config from the 'conf/' directory
    Returns:
        dict: Rules Engine Terraform definition to be marshaled to JSON
    """
    prefix = config['global']['account']['prefix']

    result = infinitedict()

    # Set variables for the rules engine IAM permissions
    result['module']['rules_engine_iam'] = {
        'source': './modules/tf_rules_engine',
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'prefix': prefix,
        'function_role_id': '${module.rules_engine_lambda.role_id}',
        'function_alias_arn': '${module.rules_engine_lambda.function_alias_arn}',
        'function_name': '${module.rules_engine_lambda.function_name}',
        'threat_intel_enabled': config.get('threat_intel', {}).get('enabled'),
        'dynamodb_table_name': config.get('threat_intel', {}).get('dynamodb_table_name'),
        'rules_table_arn': '${module.globals.rules_table_arn}',
        'enable_rule_staging':
        config['global']['infrastructure']['rule_staging'].get('enabled', False),
        'classifier_sqs_queue_arn': '${module.globals.classifier_sqs_queue_arn}',
        'classifier_sqs_sse_kms_key_arn': '${module.globals.classifier_sqs_sse_kms_key_arn}',
        'sqs_record_batch_size': min(config.get('sqs_record_batch_size', 10), 10)
    }

    environment = {'ALERTS_TABLE': f'{prefix}_streamalert_alerts', 'STREAMALERT_PREFIX': prefix}

    if config['lambda']['rules_engine_config'].get('log_rule_statistics'):
        environment['STREAMALERT_TRACK_RULE_STATS'] = '1'

    # Set variables for the Lambda module
    result['module']['rules_engine_lambda'] = generate_lambda(
        f'{prefix}_streamalert_{RULES_ENGINE_FUNCTION_NAME}',
        'streamalert.rules_engine.main.handler',
        config['lambda']['rules_engine_config'],
        config,
        environment=environment)

    return result

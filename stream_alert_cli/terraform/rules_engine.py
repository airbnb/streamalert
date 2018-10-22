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
from stream_alert.shared import RULES_ENGINE_FUNCTION_NAME
from stream_alert_cli.manage_lambda.package import RulesEnginePackage
from stream_alert_cli.terraform.common import infinitedict
from stream_alert_cli.terraform.lambda_module import generate_lambda


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
        'source': 'modules/tf_rules_engine',
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'prefix': prefix,
        'function_role_id': '${module.rules_engine_lambda.role_id}',
        'function_alias_arn': '${module.rules_engine_lambda.function_alias_arn}',
        'function_name': '${module.rules_engine_lambda.function_name}',
        'threat_intel_enabled': config.get('threat_intel', {}).get('enabled'),
        'dynamodb_table_name': config.get('threat_intel', {}).get('dynamodb_table_name'),
        'rules_table_arn': '${module.globals.rules_table_arn}',
        'classifier_sqs_queue_arn': '${module.globals.classifier_sqs_queue_arn}'
    }

    # Set variables for the Lambda module
    result['module']['rules_engine_lambda'] = generate_lambda(
        '{}_streamalert_{}'.format(prefix, RULES_ENGINE_FUNCTION_NAME),
        RulesEnginePackage.package_name + '.zip',
        RulesEnginePackage.lambda_handler,
        config['lambda']['rules_engine_config'],
        config,
        environment={
            'ALERTS_TABLE': '{}_streamalert_alerts'.format(prefix),
            'STREAMALERT_PREFIX': prefix
        }
    )

    return result

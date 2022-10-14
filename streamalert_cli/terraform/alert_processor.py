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
from streamalert.shared import ALERT_PROCESSOR_NAME
from streamalert_cli.terraform.common import infinitedict
from streamalert_cli.terraform.lambda_module import generate_lambda


def generate_alert_processor(config):
    """Generate Terraform for the Alert Processor

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        dict: Alert Processor dict to be marshaled to JSON
    """
    prefix = config['global']['account']['prefix']

    result = infinitedict()

    # Set variables for the IAM permissions module
    result['module']['alert_processor_iam'] = {
        'source':
        './modules/tf_alert_processor_iam',
        'account_id':
        config['global']['account']['aws_account_id'],
        'region':
        config['global']['account']['region'],
        'prefix':
        prefix,
        'role_id':
        '${module.alert_processor_lambda.role_id}',
        'kms_key_arn':
        '${aws_kms_key.streamalert_secrets.arn}',
        'sse_kms_key_arn':
        '${aws_kms_key.server_side_encryption.arn}',
        'output_lambda_functions': [
            # Strip qualifiers: only the function name is needed for the IAM permissions
            func.split(':')[0] for func in list(config['outputs'].get('aws-lambda', {}).values())
        ],
        'output_s3_buckets':
        list(config['outputs'].get('aws-s3', {}).values()),
        'output_sns_topics':
        list(config['outputs'].get('aws-sns', {}).values()),
        'output_sqs_queues':
        list(config['outputs'].get('aws-sqs', {}).values())
    }

    # Set variables for the Lambda module
    result['module']['alert_processor_lambda'] = generate_lambda(
        f"{config['global']['account']['prefix']}_streamalert_{ALERT_PROCESSOR_NAME}",
        'streamalert.alert_processor.main.handler',
        config['lambda']['alert_processor_config'],
        config,
        environment={
            'ALERTS_TABLE': f'{prefix}_streamalert_alerts',
            'AWS_ACCOUNT_ID': config['global']['account']['aws_account_id'],
            'STREAMALERT_PREFIX': prefix
        })

    return result

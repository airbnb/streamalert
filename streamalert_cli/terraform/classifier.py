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
from streamalert_cli.terraform.lambda_module import generate_lambda


def generate_classifier(cluster_name, cluster_dict, config):
    """Add this cluster's classifier module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    JSON Input from the config:

        {
          "classifier_config": {
            "log_level": "info",
            "log_retention_days": 14,
            "memory": 128,
            "metric_alarms": {
              "errors": {
                "enabled": true,
                "evaluation_periods": 1,
                "period_secs": 120,
                "threshold": 0
              },
              "throttles": {
                "enabled": true,
                "evaluation_periods": 1,
                "period_secs": 120,
                "threshold": 0
              }
            },
            "timeout": 60,
            "vpc_config": {
              "security_group_ids": [],
              "subnet_ids": []
            }
          }
        }
    """
    classifier_config = config['clusters'][cluster_name]['classifier_config']

    firehose_config = config['global']['infrastructure'].get('firehose', {})
    # The default value here must be consistent with the firehose client default
    use_firehose_prefix = firehose_config.get('use_prefix', True)

    tf_module_prefix = f'classifier_{cluster_name}'
    iam_module = f'{tf_module_prefix}_iam'

    # Set variables for the alert merger's IAM permissions
    cluster_dict['module'][iam_module] = {
        'source': './modules/tf_classifier',
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'prefix': config['global']['account']['prefix'],
        'firehose_use_prefix': use_firehose_prefix,
        'function_role_id': f'${{module.{tf_module_prefix}_lambda.role_id}}',
        'function_alias_arn': f'${{module.{tf_module_prefix}_lambda.function_alias_arn}}',
        'function_name': f'${{module.{tf_module_prefix}_lambda.function_name}}',
        'classifier_sqs_queue_arn': '${module.globals.classifier_sqs_queue_arn}',
        'classifier_sqs_sse_kms_key_arn': '${module.globals.classifier_sqs_sse_kms_key_arn}',
    }

    if input_config := classifier_config.get('inputs'):
        input_mapping = {'input_sns_topics': 'aws-sns'}
        for tf_key, input_key in input_mapping.items():
            if input_key in input_config:
                cluster_dict['module'][iam_module][tf_key] = input_config[input_key]

    # Set variables for the Lambda module
    cluster_dict['module'][f'{tf_module_prefix}_lambda'] = generate_lambda(
        f"{config['global']['account']['prefix']}_{cluster_name}_streamalert_classifier",
        'streamalert.classifier.main.handler',
        classifier_config,
        config,
        environment={
            'CLUSTER': cluster_name,
            'SQS_QUEUE_URL': '${module.globals.classifier_sqs_queue_url}',
        },
        tags={'Cluster': cluster_name})

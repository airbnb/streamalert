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
from stream_alert.shared import CLASSIFIER_FUNCTION_NAME
from stream_alert_cli.manage_lambda.package import ClassifierPackage
from stream_alert_cli.terraform.lambda_module import generate_lambda


def generate_classifier(cluster_name, cluster_dict, config):
    """Add this cluster's classifier module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    JSON Input from the config:

        "stream_alert": {
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
    classifier_config = (
        config['clusters'][cluster_name]['modules']['stream_alert']['classifier_config']
    )

    tf_module_prefix = 'classifier_{}'.format(cluster_name)

    # Set variables for the alert merger's IAM permissions
    cluster_dict['module']['{}_iam'.format(tf_module_prefix)] = {
        'source': 'modules/tf_classifier',
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'prefix': config['global']['account']['prefix'],
        'function_role_id': '${{module.{}_lambda.role_id}}'.format(tf_module_prefix),
        'function_alias_arn': '${{module.{}_lambda.function_alias_arn}}'.format(tf_module_prefix),
        'function_name': '${{module.{}_lambda.function_name}}'.format(tf_module_prefix),
    }

    # Add Classifier input config from the loaded cluster file
    input_config = classifier_config.get('inputs')
    if input_config:
        input_mapping = {
            'input_sns_topics': 'aws-sns'
        }
        for tf_key, input_key in input_mapping.items():
            if input_key in input_config:
                cluster_dict['module']['{}_iam'.format(tf_module_prefix)].update({
                    tf_key: input_config[input_key]
                })

    # Set variables for the Lambda module
    cluster_dict['module']['{}_lambda'.format(tf_module_prefix)] = generate_lambda(
        '{}_streamalert_classifier_{}'.format(config['global']['account']['prefix'], cluster_name),
        ClassifierPackage.package_name + '.zip',
        ClassifierPackage.lambda_handler,
        classifier_config,
        config,
        environment={
            'SQS_QUEUE_URL': '${{module.{}_iam.sqs_queue_url}}'.format(tf_module_prefix),
        },
        metrics_lookup=CLASSIFIER_FUNCTION_NAME
    )

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

def generate_stream_alert(cluster_name, cluster_dict, config):
    """Add the StreamAlert module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    JSON Input from the config:

        "stream_alert": {
          "alert_processor": {
            "current_version": "$LATEST",
            "log_level": "info",
            "memory": 128,
            "outputs": {
              "aws-lambda": [
                "lambda_function_name"
              ],
              "aws-s3": [
                "s3.bucket.name"
              ]
            },
            "timeout": 10,
            "vpc_config": {
              "security_group_ids": [
                "sg-id"
              ],
              "subnet_ids": [
                "subnet-id"
              ]
            }
          },
          "rule_processor": {
            "current_version": "$LATEST",
            "inputs": {
              "aws-sns": [
                "sns_topic_arn"
              ]
            },
            "log_level": "info",
            "memory": 128,
            "timeout": 10
          }
        }

    Returns:
        bool: Result of applying the stream_alert module
    """
    enable_metrics = config['global'].get('infrastructure',
                                          {}).get('metrics', {}).get('enabled', False)
    account = config['global']['account']
    modules = config['clusters'][cluster_name]['modules']

    cluster_dict['module']['stream_alert_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert',
        'account_id': account['aws_account_id'],
        'region': config['clusters'][cluster_name]['region'],
        'prefix': account['prefix'],
        'cluster': cluster_name,
        'kms_key_arn': '${aws_kms_key.stream_alert_secrets.arn}',
        'rule_processor_enable_metrics': enable_metrics,
        'rule_processor_log_level': modules['stream_alert'] \
            ['rule_processor'].get('log_level', 'info'),
        'rule_processor_memory': modules['stream_alert']['rule_processor']['memory'],
        'rule_processor_timeout': modules['stream_alert']['rule_processor']['timeout'],
        'rule_processor_version': modules['stream_alert']['rule_processor']['current_version'],
        'rule_processor_config': '${var.rule_processor_config}',
        'alert_processor_config': '${var.alert_processor_config}',
        'alert_processor_enable_metrics': enable_metrics,
        'alert_processor_log_level': modules['stream_alert'] \
            ['alert_processor'].get('log_level', 'info'),
        'alert_processor_memory': modules['stream_alert']['alert_processor']['memory'],
        'alert_processor_timeout': modules['stream_alert']['alert_processor']['timeout'],
        'alert_processor_version': modules['stream_alert']['alert_processor']['current_version']
    }

    # Add Alert Processor output config from the loaded cluster file
    output_config = modules['stream_alert']['alert_processor'].get('outputs')
    if output_config:
        # Mapping of Terraform input variables to output config variables
        output_mapping = {
            'output_lambda_functions': 'aws-lambda',
            'output_s3_buckets': 'aws-s3'
        }
        for tf_key, output in output_mapping.items():
            if output in output_config:
                cluster_dict['module']['stream_alert_{}'.format(cluster_name)].update({
                    tf_key: modules['stream_alert']['alert_processor']['outputs'][output]
                })

    # Add Rule Processor input config from the loaded cluster file
    input_config = modules['stream_alert']['rule_processor'].get('inputs')
    if input_config:
        input_mapping = {
            'input_sns_topics': 'aws-sns'
        }
        for tf_key, input_key in input_mapping.items():
            if input_key in input_config:
                cluster_dict['module']['stream_alert_{}'.format(cluster_name)].update({
                    tf_key: input_config[input_key]
                })

    # Add the Alert Processor VPC config from the loaded cluster file
    vpc_config = modules['stream_alert']['alert_processor'].get('vpc_config')
    if vpc_config:
        cluster_dict['module']['stream_alert_{}'.format(cluster_name)].update({
            'alert_processor_vpc_enabled': True,
            'alert_processor_vpc_subnet_ids': vpc_config['subnet_ids'],
            'alert_processor_vpc_security_group_ids': vpc_config['security_group_ids']
        })

    return True

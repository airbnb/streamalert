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
from stream_alert_cli.terraform._common import infinitedict, monitoring_topic_arn


def generate_alert_processor(config):
    """Generate Terraform for the Alert Processor

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Example Alert Processor config:
        "alert_processor_config": {
            "current_version": "$LATEST",
            "handler": "main.handler",
            "log_level": "info",
            "log_retention_days": 14,
            "memory": 128,
            "metric_alarms": {
                "enabled": True,
                "errors_alarm_threshold": 0,
                "errors_alarm_evaluation_periods": 1,
                "errors_alarm_period_secs": 120,
                "throttles_alarm_threshold": 0,
                "throttles_alarm_evaluation_periods": 1,
                "throttles_alarm_period_secs": 120
            },
            "source_bucket": "BUCKET",
            "source_object_key": "OBJECT_KEY",
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
        }

    Returns:
        dict: Alert Processor dict to be marshaled to JSON
    """
    prefix = config['global']['account']['prefix']
    alert_processor_config = config['lambda']['alert_processor_config']
    alarms_config = alert_processor_config.get('metric_alarms', {})
    outputs_config = alert_processor_config.get('outputs', {})
    vpc_config = alert_processor_config.get('vpc_config', {})

    result = infinitedict()

    # Set variables for the IAM permissions module
    result['module']['alert_processor_iam'] = {
        'source': 'modules/tf_alert_processor_iam',
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'prefix': prefix,
        'role_id': '${module.alert_processor_lambda.role_id}',
        'kms_key_arn': '${aws_kms_key.stream_alert_secrets.arn}',
        'output_lambda_functions': outputs_config.get('aws-lambda', []),
        'output_s3_buckets': outputs_config.get('aws-s3', []),
        'output_sns_topics': outputs_config.get('aws-sns', []),
        'output_sqs_queues': outputs_config.get('aws-sqs', [])
    }

    # Set variables for the Lambda module
    lambda_module = {
        'source': 'modules/tf_lambda',
        'function_name': '{}_streamalert_alert_processor'.format(prefix),
        'description': 'StreamAlert Alert Processor',
        'handler': alert_processor_config['handler'],
        'memory_size_mb': alert_processor_config['memory'],
        'timeout_sec': alert_processor_config['timeout'],
        'source_bucket': alert_processor_config['source_bucket'],
        'source_object_key': alert_processor_config['source_object_key'],
        'environment_variables': {
            'LOGGER_LEVEL': alert_processor_config.get('log_level', 'info')
        },
        'vpc_subnet_ids': vpc_config.get('subnet_ids', []),
        'vpc_security_group_ids': vpc_config.get('security_group_ids', []),
        'aliased_version': alert_processor_config['current_version'],
        'log_retention_days': alert_processor_config.get('log_retention_days', 14)
    }

    # Add metric alarms configuration
    if alarms_config.get('enabled', True):
        lambda_module['enable_metric_alarms'] = True
        lambda_module['alarm_actions'] = [monitoring_topic_arn(config)]
        for var_name, var_value in alarms_config.iteritems():
            if 'errors' in var_name or 'throttles' in var_name:
                lambda_module[var_name] = var_value
    else:
        lambda_module['enable_metric_alarms'] = False

    result['module']['alert_processor_lambda'] = lambda_module
    return result

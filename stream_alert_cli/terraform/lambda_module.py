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
from stream_alert import shared
from stream_alert_cli.terraform.common import monitoring_topic_arn


def _lambda_config(function_name, config):
    """Find the config specific to this Lambda function."""
    if function_name == shared.ALERT_PROCESSOR_NAME:
        return config['lambda']['alert_processor_config']
    else:
        raise NotImplementedError(
            'Lambda modules are not yet supported for {}'.format(function_name))


def _tf_metric_alarms(lambda_config, sns_arn):
    """Compute metric alarm Terraform configuration from the Lambda config."""
    alarms_config = lambda_config.get('metric_alarms', {})
    result = {'alarm_actions': [sns_arn]}

    for alarm_type in ['errors', 'throttles']:
        settings = alarms_config.get(alarm_type)
        if not settings or not settings.get('enabled', True):
            result['{}_alarm_enabled'.format(alarm_type)] = False
            continue

        result['{}_alarm_enabled'.format(alarm_type)] = True
        result['{}_alarm_evaluation_periods'.format(alarm_type)] = settings.get(
            'evaluation_periods', 1)
        result['{}_alarm_period_secs'.format(alarm_type)] = settings.get('period_secs', 120)
        result['{}_alarm_threshold'.format(alarm_type)] = settings.get('threshold', 0)

    return result


def generate_lambda(function_name, config, environment=None):
    """Generate an instance of the Lambda Terraform module.

    Args:
        function_name (str): Name of the Lambda function (e.g. 'alert_processor')
        config (dict): Parsed config from conf/
        environment (dict): Optional environment variables to specify.
            LOGGER_LEVEL is included automatically.

    Example Lambda config:
        {
            "concurrency_limit": 1,
            "current_version": "$LATEST",
            "handler": "main.handler",
            "invocation_frequency_minutes": 5,
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
            "source_bucket": "BUCKET",
            "source_object_key": "OBJECT_KEY",
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
        dict: Terraform config for an instance of the tf_lambda module.
    """
    lambda_config = _lambda_config(function_name, config)
    vpc_config = lambda_config.get('vpc_config', {})

    # Add logger level to any custom environment variables
    environment_variables = {
        'LOGGER_LEVEL': lambda_config.get('log_level', 'info')
    }
    if environment:
        environment_variables.update(environment)

    lambda_module = {
        'source': 'modules/tf_lambda',
        'function_name': '{}_streamalert_{}'.format(config['global']['account']['prefix'],
                                                    function_name),
        'description': 'StreamAlert {}'.format(function_name.replace('_', ' ').title()),
        'handler': lambda_config['handler'],
        'memory_size_mb': lambda_config['memory'],
        'timeout_sec': lambda_config['timeout'],
        'source_bucket': lambda_config['source_bucket'],
        'source_object_key': lambda_config['source_object_key'],
        'concurrency_limit': lambda_config.get('concurrency_limit', ''),
        'environment_variables': environment_variables,
        'vpc_subnet_ids': vpc_config.get('subnet_ids', []),
        'vpc_security_group_ids': vpc_config.get('security_group_ids', []),
        'aliased_version': lambda_config['current_version'],
        'invocation_frequency_minutes': lambda_config.get('invocation_frequency_minutes', 0),
        'log_retention_days': lambda_config.get('log_retention_days', 14)
    }

    # Add metric alarms to the Lambda module definition
    lambda_module.update(_tf_metric_alarms(lambda_config, monitoring_topic_arn(config)))

    return lambda_module

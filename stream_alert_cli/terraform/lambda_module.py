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
    result = {}
    alarms_config = lambda_config.get('metric_alarms', {})
    if not alarms_config:
        return result

    result['alarm_actions'] = [sns_arn]

    for alarm_type in ['errors', 'throttles']:
        settings = alarms_config.get(alarm_type)
        if not settings:
            continue

        for key in ['enabled', 'evaluation_periods', 'period_secs', 'threshold']:
            if key in settings:
                result['{}_alarm_{}'.format(alarm_type, key)] = settings[key]

    return result


def _tf_vpc_config(lambda_config):
    """Compute VPC configuration from the Lambda config."""
    result = {}
    vpc_config = lambda_config.get('vpc_config', {})
    if not vpc_config:
        return result

    if 'security_group_ids' in vpc_config:
        result['vpc_security_group_ids'] = vpc_config['security_group_ids']
    if 'subnet_ids' in vpc_config:
        result['vpc_subnet_ids'] = vpc_config['subnet_ids']

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
            "schedule_expression": "rate(5 minutes)",
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
        'environment_variables': environment_variables,
        'aliased_version': lambda_config['current_version'],
    }

    # Include optional keys only if they are defined (otherwise use the module defaults)
    for key in ['concurrency_limit', 'log_retention_days', 'schedule_expression']:
        if key in lambda_config:
            lambda_module[key] = lambda_config[key]

    # Add metric alarms to the Lambda module definition
    lambda_module.update(_tf_metric_alarms(lambda_config, monitoring_topic_arn(config)))

    # Add VPC config to the Lambda module definition
    lambda_module.update(_tf_vpc_config(lambda_config))

    return lambda_module

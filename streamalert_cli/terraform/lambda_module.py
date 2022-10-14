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
from streamalert_cli.terraform.common import monitoring_topic_arn


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
                result[f'{alarm_type}_alarm_{key}'] = settings[key]

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


def generate_lambda(function_name,
                    handler,
                    lambda_config,
                    config,
                    environment=None,
                    input_event=None,
                    tags=None,
                    **kwargs):
    """Generate an instance of the Lambda Terraform module.

    Args:
        function_name (str): Name of the Lambda function (e.g. 'alert_processor')
        handler (str): Lambda function handler
        lambda_config (dict): Section of the config for this particular Lambda function
        config (dict): Parsed config from conf/
        environment (dict): Optional environment variables to specify.
            ENABLE_METRICS and LOGGER_LEVEL are included automatically.
        tags (dict): Optional tags to be added to this Lambda resource.

    Keyword Args:
        include_layers (bool): Optionally include the default Lambda Layers (default: False)
        zip_file (str): Optional name for the .zip of deployment package (default: streamalert.zip)

    Example Lambda config:
        {
            "concurrency_limit": 1,
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
    # Add logger level to any custom environment variables
    environment_variables = {
        # Convert True/False to "1" or "0", respectively
        'ENABLE_METRICS': str(int(lambda_config.get('enable_custom_metrics', False))),
        'LOGGER_LEVEL': lambda_config.get('log_level', 'info')
    }

    if environment:
        environment_variables |= environment

    lambda_module = {
        'source': './modules/tf_lambda',
        'function_name': function_name,
        'description': function_name.replace('_', ' ').title(),
        'handler': handler,
        'memory_size_mb': lambda_config['memory'],
        'timeout_sec': lambda_config['timeout'],
        'environment_variables': environment_variables,
        'tags': tags or {},
    }

    if kwargs.get('include_layers', False):
        lambda_module['layers'] = '${module.globals.lamdba_layer_arns}'

    # The lambda module defaults to using the 'streamalert.zip' file that is created
    if kwargs.get('zip_file'):
        lambda_module['filename'] = kwargs.get('zip_file')

    if input_config := lambda_config.get('inputs'):
        input_mapping = {'input_sns_topics': 'aws-sns'}
        for tf_key, input_key in input_mapping.items():
            if input_key in input_config:
                lambda_module[tf_key] = input_config[input_key]

    # If the Lambda is being invoke on a schedule, an optional input event can be passed in
    if input_event:
        lambda_module['lambda_input_event'] = input_event

    # Include optional keys only if they are defined (otherwise use the module defaults)
    for key in ['concurrency_limit', 'log_retention_days', 'schedule_expression']:
        if key in lambda_config:
            lambda_module[key] = lambda_config[key]

    # Add metric alarms and filters to the Lambda module definition
    lambda_module |= _tf_metric_alarms(lambda_config, monitoring_topic_arn(config))

    # Add VPC config to the Lambda module definition
    lambda_module.update(_tf_vpc_config(lambda_config))

    return lambda_module

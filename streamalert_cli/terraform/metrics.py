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
from streamalert.shared import CLUSTERED_FUNCTIONS, metrics
from streamalert.shared.logger import get_logger
from streamalert_cli.terraform.common import infinitedict, monitoring_topic_arn

LOGGER = get_logger(__name__)


def generate_aggregate_cloudwatch_metric_filters(config):
    """Return the CloudWatch Metric Filters information for aggregate metrics

    Args:
        config (dict): The loaded config from the 'conf/' directory
    """
    functions = {
        cluster: [
            func.replace('_config', '') for func in CLUSTERED_FUNCTIONS
            if cluster_config[f'{func}_config'].get('enable_custom_metrics')
        ]
        for cluster, cluster_config in config['clusters'].items()
    }

    functions['global'] = {
        func.replace('_config', '')
        for func, func_config in config['lambda'].items()
        if func_config.get('enable_custom_metrics')
    }

    if not any(list(functions.values())):
        return  # Nothing to add if no funcs have metrics enabled

    result = infinitedict()

    current_metrics = metrics.MetricLogger.get_available_metrics()

    for cluster, functions in functions.items():
        is_global = cluster == 'global'

        for function in functions:
            # This function may not actually support any custom metrics
            if function not in current_metrics:
                continue

            metric_prefix = metrics.FUNC_PREFIXES.get(function)
            if not metric_prefix:
                continue

            log_group_name = '${{module.{}_lambda.log_group_name}}'.format(
                function) if is_global else '${{module.{}_{}_lambda.log_group_name}}'.format(
                    function, cluster)

            cluster = cluster.upper()
            if not is_global:
                cluster = f'{cluster}_AGGREGATE'

            # Add filters for the cluster and aggregate
            for metric, filter_settings in current_metrics[function].items():
                module_name = f'metric_filters_{metric_prefix}_{metric}_{cluster}'
                result['module'][module_name] = {
                    'source': './modules/tf_metric_filters',
                    'log_group_name': log_group_name,
                    'metric_name': f'{metric_prefix}-{metric}',
                    'metric_pattern': filter_settings[0],
                    'metric_value': filter_settings[1]
                }

    return result


def generate_aggregate_cloudwatch_metric_alarms(config):
    """Return any CloudWatch Metric Alarms for aggregate metrics

    Args:
        config (dict): The loaded config from the 'conf/' directory
    """
    result = infinitedict()

    sns_topic_arn = monitoring_topic_arn(config)

    for func, func_config in config['lambda'].items():
        metric_alarms = func_config.get('custom_metric_alarms')
        if not metric_alarms:
            continue

        func = func.replace('_config', '')

        for idx, name in enumerate(sorted(metric_alarms)):
            alarm_settings = metric_alarms[name]
            alarm_settings['source'] = './modules/tf_metric_alarms'
            alarm_settings['sns_topic_arn'] = sns_topic_arn
            alarm_settings['alarm_name'] = name
            result['module'][f'metric_alarm_{func}_{idx}'] = alarm_settings

    return result


def generate_cluster_cloudwatch_metric_filters(cluster_name, cluster_dict, config):
    """Add the CloudWatch Metric Filters information to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory
    """
    streamalert_config = config['clusters'][cluster_name]

    current_metrics = metrics.MetricLogger.get_available_metrics()

    # Add custom metric filters for clustered function
    for func in CLUSTERED_FUNCTIONS:
        if func not in current_metrics:
            continue

        func_config_name = f'{func}_config'
        if func_config_name not in streamalert_config:
            continue

        if not streamalert_config[func_config_name].get('enable_custom_metrics'):
            continue

        metric_prefix = metrics.FUNC_PREFIXES[func]

        log_group_name = f'${{module.{func}_{cluster_name}_lambda.log_group_name}}'

        cluster_name = cluster_name.upper()

        # Add filters for the cluster and aggregate
        for metric, filter_settings in current_metrics[func].items():
            cluster_dict['module'][f'metric_filters_{metric_prefix}_{metric}_{cluster_name}'] = {
                'source': './modules/tf_metric_filters',
                'log_group_name': log_group_name,
                'metric_name': f'{metric_prefix}-{metric}-{cluster_name}',
                'metric_pattern': filter_settings[0],
                'metric_value': filter_settings[1]
            }


def generate_cluster_cloudwatch_metric_alarms(cluster_name, cluster_dict, config):
    """Add the CloudWatch Metric Alarms information to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory
    """
    infrastructure_config = config['global'].get('infrastructure')

    if not (infrastructure_config and 'monitoring' in infrastructure_config):
        LOGGER.error('Invalid config: Make sure you declare global infrastructure options!')
        return

    sns_topic_arn = monitoring_topic_arn(config)

    streamalert_config = config['clusters'][cluster_name]

    # Add cluster metric alarms for the clustered function(s). ie: classifier
    metric_alarms = [
        metric_alarm for func in CLUSTERED_FUNCTIONS
        for metric_alarm in streamalert_config[f'{func}_config'].get('custom_metric_alarms', [])
    ]

    for idx, metric_alarm in enumerate(sorted(metric_alarms)):
        metric_alarm['source'] = './modules/tf_metric_alarms'
        metric_alarm['sns_topic_arn'] = sns_topic_arn
        cluster_dict['module'][f'metric_alarm_{cluster_name}_{idx}'] = metric_alarm

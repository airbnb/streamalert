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
from stream_alert.shared import metrics
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.terraform.common import monitoring_topic_arn


def generate_aggregate_cloudwatch_metric_filters(config):
    """Return the CloudWatch Metric Filters information for aggregate metrics

    Args:
        config (dict): The loaded config from the 'conf/' directory
    """
    functions = {
        cluster: [
            func.replace('_config', '')
            for func, func_config in cluster_config['modules']['stream_alert'].iteritems()
            if func_config.get('enable_custom_metrics')
        ] for cluster, cluster_config in config['clusters'].iteritems()
    }

    functions['global'] = {
        func.replace('_config', '') for func, func_config in config['lambda'].iteritems()
        if func_config.get('enable_custom_metrics')
    }

    if not any(funcs for funcs in functions.values()):
        return  # Nothing to add if no funcs have metrics enabled

    metrics_config = dict()

    current_metrics = metrics.MetricLogger.get_available_metrics()

    for cluster, functions in functions.iteritems():
        is_global = cluster == 'global'

        for function in functions:
            # This function may not actually support any custom metrics
            if function not in current_metrics:
                continue

            metric_prefix = metrics.FUNC_PREFIXES.get(function)
            if not metric_prefix:
                continue

            log_group_name = (
                '${{module.{}_{}_lambda.log_group_name}}'.format(function, cluster)
                if is_global else '${{module.{}_lambda.log_group_name}}'.format(function)
            )

            # Add filters for the cluster and aggregate
            for metric, filter_settings in current_metrics[function].iteritems():
                module_name = (
                    'metric_filters_{}_{}_{}'.format(metric_prefix, metric, cluster)
                    if is_global else 'metric_filters_{}_{}'.format(metric_prefix, metric)
                )
                metrics_config[module_name] = {
                    'source': 'modules/tf_metric_filters',
                    'log_group_name': log_group_name,
                    'metric_name': '{}-{}'.format(metric_prefix, metric),
                    'metric_pattern': filter_settings[0],
                    'metric_value': filter_settings[1],
                }

    return metrics_config


def generate_aggregate_cloudwatch_metric_alarms(config):
    """Return any CloudWatch Metric Alarms for aggregate metrics

    Args:
        config (dict): The loaded config from the 'conf/' directory
    """
    alarms_configs = dict()

    sns_topic_arn = monitoring_topic_arn(config)

    for func, func_config in config['lambda'].iteritems():
        metric_alarms = func_config.get('custom_metric_alarms')
        if not metric_alarms:
            continue

        func = func.replace('_config', '')

        for idx, name in enumerate(metric_alarms):
            alarm_settings = metric_alarms[name]
            alarm_settings['source'] = 'modules/tf_metric_alarms',
            alarm_settings['sns_topic_arn'] = sns_topic_arn
            alarm_settings['alarm_name'] = name
            alarms_configs['metric_alarm_{}_{}'.format(func, idx)] = alarm_settings

    return alarms_configs


def generate_cluster_cloudwatch_metric_filters(cluster_name, cluster_dict, config):
    """Add the CloudWatch Metric Filters information to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory
    """
    stream_alert_config = config['clusters'][cluster_name]['modules']['stream_alert']

    current_metrics = metrics.MetricLogger.get_available_metrics()

    # Add metric filters for the rule and alert processor
    for func, metric_prefix in metrics.FUNC_PREFIXES.iteritems():
        if func not in current_metrics:
            continue

        if func not in stream_alert_config:
            continue

        if not stream_alert_config[func].get('enable_custom_metrics'):
            continue

        log_group_name = '${{module.{}_{}_lambda.log_group_name}}'.format(func, cluster_name)

        cluster_name = cluster_name.upper()

        # Add filters for the cluster and aggregate
        for metric, filter_settings in current_metrics[func].iteritems():
            cluster_dict['module']['metric_filters_{}_{}_{}'.format(
                metric_prefix,
                metric,
                cluster_name
            )] = {
                'source': 'modules/tf_metric_filters',
                'log_group_name': log_group_name,
                'metric_name': '{}-{}-{}'.format(metric_prefix, metric, cluster_name),
                'metric_pattern': filter_settings[0],
                'metric_value': filter_settings[1],
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
        LOGGER_CLI.error(
            'Invalid config: Make sure you declare global infrastructure options!')
        return

    sns_topic_arn = monitoring_topic_arn(config)

    stream_alert_config = config['clusters'][cluster_name]['modules']['stream_alert']

    # Add cluster metric alarms for the rule and alert processors
    metric_alarms = [
        metric_alarm for func_config in stream_alert_config.values()
        for metric_alarm in func_config.get('custom_metric_alarms', [])
    ]

    for idx, metric_alarm in enumerate(metric_alarms):
        metric_alarm['source'] = 'modules/tf_metric_alarms',
        metric_alarm['sns_topic_arn'] = sns_topic_arn
        cluster_dict['module']['metric_alarm_{}_{}'.format(cluster_name, idx)] = metric_alarm

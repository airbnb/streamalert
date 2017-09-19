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
from stream_alert_cli.terraform._common import DEFAULT_SNS_MONITORING_TOPIC

def generate_cloudwatch_metric_filters(cluster_name, cluster_dict, config):
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
            LOGGER_CLI.error('Function for metrics \'%s\' is not defined in stream alert config. '
                             'Options are: %s', func,
                             ', '.join('\'{}\''.format(key) for key in stream_alert_config))
            continue

        if not stream_alert_config[func].get('enable_metrics'):
            continue

        filter_pattern_idx, filter_value_idx = 0, 1

        # Add filters for the cluster and aggregate
        # Use a list of strings that represnt the following comma separated values:
        #   <filter_name>,<filter_pattern>,<value>
        filters = []
        for metric, settings in current_metrics[func].items():
            filters.extend([
                '{},{},{}'.format(
                    '{}-{}-{}'.format(metric_prefix, metric, cluster_name.upper()),
                    settings[filter_pattern_idx],
                    settings[filter_value_idx]),
                '{},{},{}'.format(
                    '{}-{}'.format(metric_prefix, metric),
                    settings[filter_pattern_idx],
                    settings[filter_value_idx])
            ])

        cluster_dict['module']['stream_alert_{}'.format(cluster_name)] \
            ['{}_metric_filters'.format(func)] = filters


def _format_metric_alarm(name, alarm_settings):
    """Helper function to format a metric alarm as a comma-separated string

    Args:
        name (str): The name of the alarm to create
        alarm_info (dict): All other settings for this alarm (threshold, etc)
        function (str): The respective function this alarm is being created for.
            This is the RuleProcessor or AlertProcessor
        cluster (str): The cluster that this metric is related to

    Returns:
        str: formatted and comma-separated string containing alarm settings
    """
    alarm_info = alarm_settings.copy()
    # The alarm description and name can potentially have commas so remove them
    alarm_info['alarm_description'] = alarm_info['alarm_description'].replace(',', '')

    attributes = list(alarm_info)
    attributes.sort()
    sorted_values = [str(alarm_info[attribute]) if alarm_info[attribute]
                     else '' for attribute in attributes]

    sorted_values.insert(0, name.replace(',', ''))

    return ','.join(sorted_values)


def generate_cloudwatch_metric_alarms(cluster_name, cluster_dict, config):
    """Add the CloudWatch Metric Alarms information to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory
    """
    infrastructure_config = config['global'].get('infrastructure')

    if not (infrastructure_config and 'monitoring' in infrastructure_config):
        LOGGER_CLI.error('Invalid config: Make sure you declare global infrastructure options!')
        return

    topic_name = (DEFAULT_SNS_MONITORING_TOPIC if infrastructure_config
                  ['monitoring'].get('create_sns_topic') else
                  infrastructure_config['monitoring'].get('sns_topic_name'))

    sns_topic_arn = 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
        region=config['global']['account']['region'],
        account_id=config['global']['account']['aws_account_id'],
        topic=topic_name
    )

    cluster_dict['module']['stream_alert_{}'.format(cluster_name)] \
        ['sns_topic_arn'] = sns_topic_arn

    stream_alert_config = config['clusters'][cluster_name]['modules']['stream_alert']

    # Add cluster metric alarms for the rule and alert processors
    formatted_alarms = []
    for func_config in stream_alert_config.values():
        if 'metric_alarms' not in func_config:
            continue

        # TODO: update this logic to simply use a list of maps once Terraform fixes
        # their support for this, instead of the comma-separated string this creates
        metric_alarms = func_config['metric_alarms']
        for name, alarm_info in metric_alarms.iteritems():
            formatted_alarms.append(
                _format_metric_alarm(name, alarm_info)
            )

    cluster_dict['module']['stream_alert_{}'.format(cluster_name)] \
        ['metric_alarms'] = formatted_alarms

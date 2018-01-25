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
from stream_alert_cli.logger import LOGGER_CLI


def generate_monitoring(cluster_name, cluster_dict, config):
    """Add the CloudWatch Monitoring module to the Terraform cluster dict.

    Example configuration:

    "cloudwatch_monitoring": {
      "enabled": true,
      "kinesis_alarms_enabled": true,
      "lambda_alarms_enabled": true,
      "settings": {
        "lambda_invocation_error_period": "600",
        "kinesis_iterator_age_error_period": "600",
        "kinesis_write_throughput_exceeded_threshold": "100"
      }
    }

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the cloudwatch_monitoring module
    """
    prefix = config['global']['account']['prefix']
    infrastructure_config = config['global'].get('infrastructure')
    monitoring_config = config['clusters'][cluster_name]['modules']['cloudwatch_monitoring']
    sns_topic_arn = None

    if not (infrastructure_config and 'monitoring' in infrastructure_config):
        LOGGER_CLI.error('Invalid config: Make sure you declare global infrastructure options!')
        return False

    if not monitoring_config.get('enabled', False):
        LOGGER_CLI.info('CloudWatch Monitoring not enabled, skipping...')
        return True

    if infrastructure_config['monitoring'].get('create_sns_topic'):
        topic_name = 'stream_alert_monitoring'

    elif infrastructure_config['monitoring'].get('sns_topic_name'):
        topic_name = infrastructure_config['monitoring']['sns_topic_name']

    sns_topic_arn = 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
        region=config['global']['account']['region'],
        account_id=config['global']['account']['aws_account_id'],
        topic=topic_name)

    cluster_dict['module']['cloudwatch_monitoring_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert_monitoring',
        'sns_topic_arn': sns_topic_arn,
        'kinesis_alarms_enabled': False,
        'lambda_alarms_enabled': False
    }

    if monitoring_config.get('lambda_alarms_enabled', True):
        cluster_dict['module']['cloudwatch_monitoring_{}'.format(cluster_name)].update({
            'lambda_functions': [
                '{}_{}_streamalert_rule_processor'.format(prefix, cluster_name),
                '{}_{}_streamalert_alert_processor'.format(prefix, cluster_name)
            ],
            'lambda_alarms_enabled': True
        })

    if monitoring_config.get('kinesis_alarms_enabled', True):
        cluster_dict['module']['cloudwatch_monitoring_{}'.format(cluster_name)].update({
            'kinesis_stream': '{}_{}_stream_alert_kinesis'.format(prefix, cluster_name),
            'kinesis_alarms_enabled': True
        })

    # Add support for custom settings for tweaking alarm thresholds, eval periods, and periods
    # Note: This does not strictly check for proper variable names, since there are so many.
    #       Instead, Terraform will error out if an imporper name is used.
    #       Also, every value in these settings should be a string, so cast for safety.
    for setting_name, setting_value in monitoring_config.get('settings', {}).iteritems():
        cluster_dict['module']['cloudwatch_monitoring_{}'.format(
            cluster_name)][setting_name] = str(setting_value)

    return True

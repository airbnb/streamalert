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
import json

from stream_alert_cli.terraform._common import DEFAULT_SNS_MONITORING_TOPIC


def generate_app_integrations(cluster_name, cluster_dict, config):
    """Add the app integrations module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for
                                    a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the app integration module
    """
    # Use the monitoring topic as a dead letter queue
    infrastructure_config = config['global'].get('infrastructure')
    dlq_topic = (DEFAULT_SNS_MONITORING_TOPIC
                 if infrastructure_config.get('monitoring', {}).get('create_sns_topic')
                 else infrastructure_config.get('monitoring', {}).get('sns_topic_name',
                                                                      DEFAULT_SNS_MONITORING_TOPIC))

    prefix = config['global']['account']['prefix']

    # App integration modules
    for app_name, app_info in config['clusters'][cluster_name] \
        ['modules'].get('stream_alert_apps', {}).iteritems():
        func_prefix = '_'.join([prefix, cluster_name, app_info['type'], app_name])
        config_param = json.dumps({'type': app_info['type'],
                                   'app_name': app_name,
                                   'prefix': prefix,
                                   'cluster': cluster_name,
                                   'interval': app_info['interval']})

        cluster_dict['module']['app_{}_{}'.format(app_name, cluster_name)] = {
            'account_id': config['global']['account']['aws_account_id'],
            'cluster': cluster_name,
            'region': config['global']['account']['region'],
            'prefix': prefix,
            'function_prefix': func_prefix,
            'type': app_info['type'],
            'app_name': app_name,
            'interval': app_info['interval'],
            'current_version': app_info['current_version'],
            'app_memory': app_info['memory'],
            'app_timeout': app_info['timeout'],
            'stream_alert_apps_config': '${var.stream_alert_apps_config}',
            'log_level': app_info['log_level'],
            'source': 'modules/tf_stream_alert_app',
            'app_config_parameter': config_param,
            'monitoring_sns_topic': dlq_topic
        }

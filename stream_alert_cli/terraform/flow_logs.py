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

def generate_flow_logs(cluster_name, cluster_dict, config):
    """Add the VPC Flow Logs module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the flow_logs module
    """
    modules = config['clusters'][cluster_name]['modules']
    flow_log_group_name_default = '{}_{}_streamalert_flow_logs'.format(
        config['global']['account']['prefix'],
        cluster_name
    )
    flow_log_group_name = modules['flow_logs'].get(
        'log_group_name', flow_log_group_name_default)

    if modules['flow_logs']['enabled']:
        cluster_dict['module']['flow_logs_{}'.format(cluster_name)] = {
            'source': 'modules/tf_stream_alert_flow_logs',
            'destination_stream_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
            'flow_log_group_name': flow_log_group_name}
        for flow_log_input in ('vpcs', 'subnets', 'enis'):
            input_data = modules['flow_logs'].get(flow_log_input)
            if input_data:
                cluster_dict['module']['flow_logs_{}'.format(
                    cluster_name)][flow_log_input] = input_data
        return True

    LOGGER_CLI.info('Flow logs disabled, nothing to do')

    return False

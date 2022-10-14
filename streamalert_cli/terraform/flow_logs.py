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
from streamalert.shared.logger import get_logger
from streamalert_cli.terraform.cloudwatch_destinations import \
    generate_cloudwatch_destinations_internal

LOGGER = get_logger(__name__)

DEFAULT_FLOW_LOG_TYPES = ['vpcs', 'subnets', 'enis']


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
    if not modules['flow_logs'].get('enabled', True):
        LOGGER.debug('Flow logs disabled, nothing to do')
        return True  # not an error

    prefix = config['global']['account']['prefix']
    region = config['global']['account']['region']

    # If 'vpcs', 'subnets', or 'enis' is defined within the config, we should create
    # flow logs for these values
    create_flow_logs = any(modules['flow_logs'].get(flow_log_type)
                           for flow_log_type in DEFAULT_FLOW_LOG_TYPES)

    if not create_flow_logs:
        LOGGER.error(
            'Flow logs is enabled for cluster \'%s\', but none of the following are specified: %s',
            cluster_name, DEFAULT_FLOW_LOG_TYPES)
        return False

    dest_fmt = '${{module.cloudwatch_logs_destination_{}_{}.cloudwatch_logs_destination_arn}}'
    flow_logs_settings = {
        'source': './modules/tf_flow_logs',
        'prefix': prefix,
        'cluster': cluster_name,
        'cloudwatch_logs_destination_arn': dest_fmt.format(cluster_name, region),
    }

    variables_with_defaults = ['log_retention', 'flow_log_filter']
    for variable in variables_with_defaults:
        if variable in modules['flow_logs']:
            flow_logs_settings[variable] = modules['flow_logs'][variable]

    for flow_log_type in DEFAULT_FLOW_LOG_TYPES:
        if values := modules['flow_logs'].get(flow_log_type):
            flow_logs_settings[flow_log_type] = values

    cluster_dict['module'][f'flow_logs_{cluster_name}'] = flow_logs_settings

    # Add the additional settings to allow for internal flow log sending
    return generate_cloudwatch_destinations_internal(cluster_name, cluster_dict, config)

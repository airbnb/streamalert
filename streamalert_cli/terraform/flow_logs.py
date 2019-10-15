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
from streamalert.shared.logger import get_logger

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
    if not modules['flow_logs']['enabled']:
        LOGGER.info('Flow logs disabled, nothing to do')
        return False

    prefix = config['global']['account']['prefix']
    region = config['global']['account']['region']
    all_account_ids = modules['flow_logs'].get('cross_account_ids', [])

    # If 'vpcs', 'subnets', or 'enis' is defined within the config, we should create
    # flow logs for these values
    create_internal_flow_logs = any(
        modules['flow_logs'].get(flow_log_type)
        for flow_log_type in DEFAULT_FLOW_LOG_TYPES
    )
    if create_internal_flow_logs:
        flow_logs_settings = {
            'source': 'modules/tf_flow_logs/modules/internal',
            'region': region,
            'prefix': prefix,
            'cluster': cluster_name,
            'cloudwatch_log_destination_arn': (
                '${{module.flow_logs_default_{}.cloudwatch_log_destination_arn}}'.format(
                    cluster_name
                )
            ),
        }

        variables_with_defaults = ['log_retention', 'flow_log_filter']
        for variable in variables_with_defaults:
            if variable in modules['flow_logs']:
                flow_logs_settings[variable] = modules['flow_logs'][variable]

        for flow_log_type in DEFAULT_FLOW_LOG_TYPES:
            values = modules['flow_logs'].get(flow_log_type)
            if values:
                flow_logs_settings[flow_log_type] = values

        cluster_dict['module']['flow_logs_internal_{}'.format(cluster_name)] = flow_logs_settings

        # Append the home account id
        all_account_ids.append(config['global']['account']['aws_account_id'])

    # Add the default settings to allow for internal and cross-account flow log sending
    cluster_dict['module']['flow_logs_default_{}'.format(cluster_name)] = {
        'source': 'modules/tf_flow_logs/modules/default',
        'region': region,
        'prefix': prefix,
        'cluster': cluster_name,
        'account_ids': all_account_ids,
        'destination_stream_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
    }

    return True

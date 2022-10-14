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

LOGGER = get_logger(__name__)


def generate_cloudwatch_destinations(cluster_name, cluster_dict, config):
    """Add any CloudWatch Logs destinations for explicitly specified regions

    These configuration options will be merged with any other options set
    for use with various other modules that utilize CloudWatch Logs destinations:
        tf_flow_logs
        tf_cloudtrail

    Args:
        cluster_name (str): The name of the current cluster being generated
        cluster_dict (defaultdict): The dict containing all Terraform config for
            a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: True if this module was applied successfully, False otherwise
    """
    cloudwatch_module = config['clusters'][cluster_name]['modules']['cloudwatch_logs_destination']
    if not cloudwatch_module.get('enabled'):
        LOGGER.debug('CloudWatch destinations module is not enabled')
        return True  # not an error

    account_ids = cloudwatch_module.get('cross_account_ids', [])
    regions = cloudwatch_module.get('regions')
    if not regions:
        LOGGER.error(
            'CloudWatch destinations must be enabled for at '
            'least one region in the \'%s\' cluster', cluster_name)
        return False

    return _generate(cluster_name, cluster_dict, config, account_ids, regions)


def generate_cloudwatch_destinations_internal(cluster_name, cluster_dict, config):
    """Add any CloudWatch Logs destinations needed for internal usage (non-cross-account)

    This is currently used to configure additional settings for the following modules:
        tf_flow_logs
        tf_cloudtrail

    These configuration options will be merged with any other options set for use in
    the tf_cloudwatch_logs_destination module.

    Args:
        cluster_name (str): The name of the current cluster being generated
        cluster_dict (defaultdict): The dict containing all Terraform config for
            a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: True if this module was applied successfully, False otherwise
    """
    account_ids = [config['global']['account']['aws_account_id']]
    regions = [config['global']['account']['region']]
    return _generate(cluster_name, cluster_dict, config, account_ids, regions)


def _generate(cluster_name, cluster_dict, config, account_ids, regions):
    """Add the CloudWatch destinations, mapping to the configured kinesis stream

    Args:
        cluster_name (str): The name of the current cluster being generated
        cluster_dict (defaultdict): The dict containing all Terraform config for
            a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: True if this module was applied successfully, False otherwise
    """
    # Ensure that the kinesis module is enabled for this cluster since the
    # cloudwatch module will utilize the created stream for sending data
    if not config['clusters'][cluster_name]['modules'].get('kinesis'):
        LOGGER.error('The \'kinesis\' module must be enabled to enable the '
                     '\'cloudwatch\' module.')
        return False

    parent_module_name = f'cloudwatch_logs_destination_{cluster_name}'

    prefix = config['global']['account']['prefix']
    stream_arn = f'${{module.kinesis_{cluster_name}.arn}}'

    # Merge these regions with any that are already in the configuration
    all_regions = sorted(
        set(cluster_dict['module'][parent_module_name].get('regions', [])).union(set(regions)))

    cluster_dict['module'][parent_module_name] = {
        'source': './modules/tf_cloudwatch_logs_destination',
        'prefix': prefix,
        'cluster': cluster_name,
        'regions': all_regions,
        'destination_kinesis_stream_arn': stream_arn,
    }

    for region in all_regions:
        module_name = f'cloudwatch_logs_destination_{cluster_name}_{region}'

        # Merge these account IDs with any that are already in the configuration
        all_account_ids = set(cluster_dict['module'][module_name].get('account_ids',
                                                                      [])).union(set(account_ids))

        cluster_dict['module'][module_name] = {
            'source':
            './modules/tf_cloudwatch_logs_destination/modules/destination',
            'prefix':
            prefix,
            'cluster':
            cluster_name,
            'account_ids':
            sorted(all_account_ids),
            'destination_kinesis_stream_arn':
            stream_arn,
            'cloudwatch_logs_subscription_role_arn':
            (f'${{module.{parent_module_name}.cloudwatch_logs_subscription_role_arn}}'),
            'providers': {
                'aws': f'aws.{region}'
            }
        }

    return True

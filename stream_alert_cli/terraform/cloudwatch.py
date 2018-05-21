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


def generate_cloudwatch(cluster_name, cluster_dict, config):
    """Add the CloudWatch destinations, mapping to the configured kinesis stream

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for
                                    a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the cloudwatch module
    """
    cloudwatch_module = config['clusters'][cluster_name]['modules']['cloudwatch']

    if not cloudwatch_module.get('enabled', True):
        LOGGER_CLI.info('The \'cloudwatch\' module is not enabled, nothing to do.')
        return True

    # Ensure that the kinesis module is enabled for this cluster since the
    # cloudwatch module will utilize the created stream for sending data
    if not config['clusters'][cluster_name]['modules'].get('kinesis'):
        LOGGER_CLI.error('The \'kinesis\' module must be enabled to enable the '
                         '\'cloudwatch\' module.')
        return False

    account_id = config['global']['account']['aws_account_id']
    cross_account_ids = cloudwatch_module.get('cross_account_ids', []) + [account_id]
    excluded_regions = set(cloudwatch_module.get('excluded_regions', set()))

    # Exclude any desired regions from the entire list of regions
    regions = {
        'ap-northeast-1',
        'ap-northeast-2',
        'ap-south-1',
        'ap-southeast-1',
        'ap-southeast-2',
        'ca-central-1',
        'eu-central-1',
        'eu-west-1',
        'eu-west-2',
        'eu-west-3',
        'sa-east-1',
        'us-east-1',
        'us-east-2',
        'us-west-1',
        'us-west-2',
    }.difference(excluded_regions)

    for region in regions:
        cluster_dict['module']['cloudwatch_{}_{}'.format(cluster_name, region)] = {
            'source': 'modules/tf_stream_alert_cloudwatch',
            'region': region,
            'cross_account_ids': cross_account_ids,
            'cluster': cluster_name,
            'kinesis_stream_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name)
        }

    return True

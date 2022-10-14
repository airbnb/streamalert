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
import json
from collections import defaultdict

from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)

# From here: http://amzn.to/2zF7CS0
VALID_EVENT_PATTERN_KEYS = {
    'version',
    'id',
    'detail-type',
    'source',
    'account',
    'time',
    'region',
    'resources',
    'detail',
}


def generate_cloudwatch_events(cluster_name, cluster_dict, config):
    """Add the CloudWatch Events module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the cloudwatch events module
    """
    modules = config['clusters'][cluster_name]['modules']
    settings = modules['cloudwatch_events']
    if not settings.get('enabled', True):
        LOGGER.debug('CloudWatch events module is not enabled')
        return True  # not an error

    tf_module_name = f'cloudwatch_events_{cluster_name}'

    # Using this syntax to allow for override via empty event pattern
    event_pattern = None
    if 'event_pattern' in settings:
        event_pattern = settings['event_pattern']
        if event_pattern and not set(event_pattern).issubset(VALID_EVENT_PATTERN_KEYS):
            LOGGER.error('Invalid CloudWatch event pattern: %s', json.dumps(event_pattern))
            return False
    else:
        event_pattern = {'account': [config['global']['account']['aws_account_id']]}

    cluster_dict['module'][tf_module_name] = {
        'source': './modules/tf_cloudwatch_events',
        'cluster': cluster_name,
        'prefix': config['global']['account']['prefix'],
        'kinesis_arn': f'${{module.kinesis_{cluster_name}.arn}}',
        # None == null in json objects and terraform 12 supports null variables
        'event_pattern': json.dumps(event_pattern) if event_pattern is not None else event_pattern
    }

    cross_account_settings = settings.get('cross_account')
    if not cross_account_settings:
        return True

    region_map = _map_regions(cross_account_settings)
    for region, values in region_map.items():
        tf_module_name = f'cloudwatch_events_cross_account_{cluster_name}_{region}'
        cluster_dict['module'][tf_module_name] = {
            'source': './modules/tf_cloudwatch_events/cross_account',
            'region': region,
            'accounts': sorted(values.get('accounts', [])),
            'organizations': sorted(values.get('organizations', [])),
            'providers': {
                'aws': f'aws.{region}'
            }
        }

    return True


def _map_regions(settings):
    """Reverse the mapping of accounts/orgs <> regions to make it nicer for terraform to use

    Args:
        settings (dict): Mapping or accounts/orgs to regions
            Example:
                {
                    'accounts': {
                        '123456789012': ['us-east-1'],
                        '234567890123': ['us-east-1']
                    },
                    'organizations': {
                        'o-aabbccddee': ['us-west-1']
                    }
                }

    Returns:
        dict: An inverse mapping of regions <> accounts/orgs
            Example:
                {
                    'us-east-1': {
                        'accounts': ['123456789012', '234567890123'],
                    },
                    'us-west-1': {
                        'organizations': ['o-aabbccddee']
                    }
                }
    """
    region_map = defaultdict(dict)
    for scope in ['accounts', 'organizations']:
        for aws_id, regions in settings.get(scope, {}).items():
            for region in regions:
                region_map[region] = region_map.get(region, defaultdict(list))
                region_map[region][scope].append(aws_id)

    return region_map

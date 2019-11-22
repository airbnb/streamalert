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

from streamalert.shared.logger import get_logger
from streamalert_cli.terraform.cloudwatch import generate_cloudwatch_destinations_internal

LOGGER = get_logger(__name__)


def generate_cloudtrail(cluster_name, cluster_dict, config):
    """Add the CloudTrail module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the cloudtrail module
    """
    modules = config['clusters'][cluster_name]['modules']
    cloudtrail_module = 'cloudtrail_{}'.format(cluster_name)

    cloudtrail_enabled = modules['cloudtrail'].get('enable_logging', True)
    kinesis_enabled = modules['cloudtrail'].get('enable_kinesis', True)
    send_to_cloudwatch = modules['cloudtrail'].get('send_to_cloudwatch', False)
    exclude_home_region = modules['cloudtrail'].get('exclude_home_region_events', False)

    account_ids = set(modules['cloudtrail'].get('cross_account_ids', []))
    account_ids.add(config['global']['account']['aws_account_id'])

    existing_trail = modules['cloudtrail'].get('existing_trail', False)
    is_global_trail = modules['cloudtrail'].get('is_global_trail', True)
    region = config['global']['account']['region']

    event_pattern_default = {'account': [config['global']['account']['aws_account_id']]}
    event_pattern = modules['cloudtrail'].get('event_pattern', event_pattern_default)

    # From here: http://amzn.to/2zF7CS0
    valid_event_pattern_keys = {
        'version', 'id', 'detail-type', 'source', 'account', 'time', 'region', 'resources', 'detail'
    }
    if not set(event_pattern.keys()).issubset(valid_event_pattern_keys):
        LOGGER.error('Config Error: Invalid CloudWatch Event Pattern!')
        return False

    module_info = {
        'source': './modules/tf_cloudtrail',
        'primary_account_id': config['global']['account']['aws_account_id'],
        'account_ids': sorted(account_ids),
        'cluster': cluster_name,
        'prefix': config['global']['account']['prefix'],
        'enable_logging': cloudtrail_enabled,
        'enable_kinesis': kinesis_enabled,
        's3_logging_bucket': config['global']['s3_access_logging']['logging_bucket'],
        'existing_trail': existing_trail,
        'send_to_cloudwatch': send_to_cloudwatch,
        'exclude_home_region_events': exclude_home_region,
        'region': region,
        'is_global_trail': is_global_trail
    }

    # use the kinesis output from the kinesis streams module
    if kinesis_enabled:
        module_info['kinesis_arn'] = '${{module.kinesis_{}.arn}}'.format(cluster_name)
        module_info['event_pattern'] = json.dumps(event_pattern)

    if send_to_cloudwatch:
        destination_arn = modules['cloudtrail'].get('cloudwatch_destination_arn')
        if not destination_arn:
            fmt = '${{module.cloudwatch_logs_destination_{}_{}.cloudwatch_logs_destination_arn}}'
            destination_arn = fmt.format(cluster_name, region)
            if not generate_cloudwatch_destinations_internal(cluster_name, cluster_dict, config):
                return False

        module_info['cloudwatch_destination_arn'] = destination_arn

    cluster_dict['module'][cloudtrail_module] = module_info

    return True

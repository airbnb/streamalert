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

from stream_alert_cli.logger import LOGGER_CLI

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
    cloudtrail_enabled = bool(modules['cloudtrail']['enabled'])
    existing_trail_default = False
    existing_trail = modules['cloudtrail'].get('existing_trail', existing_trail_default)
    is_global_trail_default = True
    is_global_trail = modules['cloudtrail'].get(
        'is_global_trail', is_global_trail_default)
    event_pattern_default = {
        'account': [config['global']['account']['aws_account_id']]
    }
    event_pattern = modules['cloudtrail'].get('event_pattern', event_pattern_default)

    # From here:
    # http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/CloudWatchEventsandEventPatterns.html
    valid_event_pattern_keys = {
        'version',
        'id',
        'detail-type',
        'source',
        'account',
        'time',
        'region',
        'resources',
        'detail'
    }
    if not set(event_pattern.keys()).issubset(valid_event_pattern_keys):
        LOGGER_CLI.error('Invalid CloudWatch Event Pattern!')
        return False

    cluster_dict['module']['cloudtrail_{}'.format(cluster_name)] = {
        'account_id': config['global']['account']['aws_account_id'],
        'cluster': cluster_name,
        'kinesis_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
        'prefix': config['global']['account']['prefix'],
        'enable_logging': cloudtrail_enabled,
        'source': 'modules/tf_stream_alert_cloudtrail',
        's3_logging_bucket': '{}.streamalert.s3-logging'.format(
            config['global']['account']['prefix']),
        'existing_trail': existing_trail,
        'is_global_trail': is_global_trail,
        'event_pattern': json.dumps(event_pattern)
    }

    return True

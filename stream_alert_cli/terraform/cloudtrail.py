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
    cloudtrail_module = 'cloudtrail_{}'.format(cluster_name)

    enabled_legacy = modules['cloudtrail'].get('enabled')

    cloudtrail_enabled = modules['cloudtrail'].get('enable_logging', True)
    kinesis_enabled = modules['cloudtrail'].get('enable_kinesis', True)

    account_ids = list(
        set([config['global']['account']['aws_account_id']] + modules['cloudtrail'].get(
            'cross_account_ids', [])))

    # Allow for backwards compatilibity
    if enabled_legacy:
        del config['clusters'][cluster_name]['modules']['cloudtrail']['enabled']
        config['clusters'][cluster_name]['modules']['cloudtrail']['enable_logging'] = True
        config['clusters'][cluster_name]['modules']['cloudtrail']['enable_kinesis'] = True
        LOGGER_CLI.info('Converting legacy CloudTrail config')
        config.write()
        kinesis_enabled = True
        cloudtrail_enabled = True

    existing_trail = modules['cloudtrail'].get('existing_trail', False)
    is_global_trail = modules['cloudtrail'].get('is_global_trail', True)

    event_pattern_default = json.dumps({'account': [config['global']['account']['aws_account_id']]})
    try:
        event_pattern = json.loads(modules['cloudtrail'].get('event_pattern',
                                                             event_pattern_default))
    except ValueError:
        LOGGER_CLI.error('Event Pattern is not valid JSON')
        return False

    # From here: http://amzn.to/2zF7CS0
    valid_event_pattern_keys = {
        'version', 'id', 'detail-type', 'source', 'account', 'time', 'region', 'resources', 'detail'
    }
    if not set(event_pattern.keys()).issubset(valid_event_pattern_keys):
        LOGGER_CLI.error('Config Error: Invalid CloudWatch Event Pattern!')
        return False

    cluster_dict['module'][cloudtrail_module] = {
        'source': 'modules/tf_stream_alert_cloudtrail',
        'account_ids': account_ids,
        'cluster': cluster_name,
        'prefix': config['global']['account']['prefix'],
        'enable_logging': cloudtrail_enabled,
        'enable_kinesis': kinesis_enabled,
        's3_logging_bucket':
        '{}.streamalert.s3-logging'.format(config['global']['account']['prefix']),
        'existing_trail': existing_trail,
        'is_global_trail': is_global_trail
    }

    if kinesis_enabled:
        cluster_dict['module'][cloudtrail_module][
            'kinesis_arn'] = '${{module.kinesis_{}.arn}}'.format(cluster_name)
        cluster_dict['module'][cloudtrail_module]['event_pattern'] = json.dumps(event_pattern)

    return True

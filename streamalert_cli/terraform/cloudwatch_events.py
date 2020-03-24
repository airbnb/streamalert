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

    tf_module_name = 'cloudwatch_events_{}'.format(cluster_name)

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
        'kinesis_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
        # None == null in json objects and terraform 12 supports null variables
        'event_pattern': json.dumps(event_pattern) if event_pattern is not None else event_pattern
    }

    return True

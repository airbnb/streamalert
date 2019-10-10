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


def generate_s3_events(cluster_name, cluster_dict, config):
    """Add the S3 Events module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the s3_events module
    """
    modules = config['clusters'][cluster_name]['modules']
    prefix = config['global']['account']['prefix']
    s3_event_buckets = modules['s3_events']

    # Detect legacy and convert
    if isinstance(s3_event_buckets, dict) and 's3_bucket_id' in s3_event_buckets:
        del config['clusters'][cluster_name]['modules']['s3_events']
        s3_event_buckets = [{'bucket_id': s3_event_buckets['s3_bucket_id']}]
        config['clusters'][cluster_name]['modules']['s3_events'] = s3_event_buckets
        LOGGER.info('Converting legacy S3 Events config')
        config.write()

    # Add each configured S3 bucket module
    for index, bucket_info in enumerate(s3_event_buckets):
        if 'bucket_id' not in bucket_info:
            LOGGER.error('Config Error: Missing bucket_id key from s3_event configuration')
            return False

        cluster_dict['module']['s3_events_{}_{}_{}'.format(prefix, cluster_name, index)] = {
            'source': './modules/tf_s3_events',
            'lambda_role_id': '${{module.classifier_{}_lambda.role_id}}'.format(cluster_name),
            'lambda_function_alias': (
                '${{module.classifier_{}_lambda.function_alias}}'.format(cluster_name)
            ),
            'lambda_function_alias_arn': (
                '${{module.classifier_{}_lambda.function_alias_arn}}'.format(cluster_name)
            ),
            'lambda_function_name': (
                '${{module.classifier_{}_lambda.function_name}}'.format(cluster_name)
            ),
            'bucket_id': bucket_info['bucket_id'],
            'notification_id': '{}_{}'.format(cluster_name, index),
            'enable_events': bucket_info.get('enable_events', True),
            'filter_prefix': bucket_info.get('filter_prefix', ''),
            'filter_suffix': bucket_info.get('filter_suffix', '')
        }

    return True

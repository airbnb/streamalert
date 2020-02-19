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
import re

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
    s3_event_buckets = config['clusters'][cluster_name]['modules']['s3_events']
    generate_s3_events_by_bucket(cluster_name, cluster_dict, config, s3_event_buckets)
    return True


def generate_s3_events_by_bucket(cluster_name, cluster_dict, config, buckets, module_prefix=None):
    """Helper function to add the S3 Events module to the cluster dict for a given buckets config

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the s3_events module
    """
    prefix = config['global']['account']['prefix']
    lambda_module_path = 'module.classifier_{}_lambda'.format(cluster_name)

    module_prefix = '{}s3_events_{}_{}'.format(
        '' if not module_prefix else '{}_'.format(module_prefix),
        prefix,
        cluster_name
    )

    # Add each configured S3 bucket module
    for bucket_name, info in buckets.items():
        # Replace all invalid module characters with underscores
        mod_suffix = re.sub('[^a-zA-Z0-9_-]', '_', bucket_name)
        cluster_dict['module']['{}_{}'.format(module_prefix, mod_suffix)] = {
            'source': './modules/tf_s3_events',
            'lambda_role_id': '${{{}.role_id}}'.format(lambda_module_path),
            'lambda_function_alias': '${{{}.function_alias}}'.format(lambda_module_path),
            'lambda_function_alias_arn': '${{{}.function_alias_arn}}'.format(lambda_module_path),
            'lambda_function_name': '${{{}.function_name}}'.format(lambda_module_path),
            'bucket_name': bucket_name,
            'filters': info
        }

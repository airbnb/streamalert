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
    lambda_module_path = f'module.classifier_{cluster_name}_lambda'

    module_prefix = f"{f'{module_prefix}_' if module_prefix else ''}s3_events_{prefix}_{cluster_name}"

    # Add each configured S3 bucket module
    for bucket_name, info in buckets.items():
        # Replace all invalid module characters with underscores
        mod_suffix = re.sub('[^a-zA-Z0-9_-]', '_', bucket_name)
        cluster_dict['module'][f'{module_prefix}_{mod_suffix}'] = {
            'source': './modules/tf_s3_events',
            'lambda_role_id': f'${{{lambda_module_path}.role_id}}',
            'lambda_function_alias': f'${{{lambda_module_path}.function_alias}}',
            'lambda_function_alias_arn': f'${{{lambda_module_path}.function_alias_arn}}',
            'lambda_function_name': f'${{{lambda_module_path}.function_name}}',
            'bucket_name': bucket_name,
            'filters': info
        }

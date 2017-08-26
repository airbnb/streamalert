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
    s3_bucket_id = modules['s3_events'].get('s3_bucket_id')

    if not s3_bucket_id:
        LOGGER_CLI.error(
            'Config Error: Missing S3 bucket in %s s3_events module',
            cluster_name)
        return False

    cluster_dict['module']['s3_events_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert_s3_events',
        'lambda_function_arn': '${{module.stream_alert_{}.lambda_arn}}'.format(cluster_name),
        'lambda_function_name': '{}_{}_stream_alert_processor'.format(
            config['global']['account']['prefix'],
            cluster_name),
        's3_bucket_id': s3_bucket_id,
        's3_bucket_arn': 'arn:aws:s3:::{}'.format(s3_bucket_id),
        'lambda_role_id': '${{module.stream_alert_{}.lambda_role_id}}'.format(cluster_name),
        'lambda_role_arn': '${{module.stream_alert_{}.lambda_role_arn}}'.format(cluster_name)}

    return True

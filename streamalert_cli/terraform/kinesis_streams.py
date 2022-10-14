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
from streamalert_cli.terraform.common import generate_tf_outputs


def generate_kinesis_streams(cluster_name, cluster_dict, config):
    """Add the Kinesis Streams module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for
                                    a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the kinesis module
    """
    prefix = config['global']['account']['prefix']
    kinesis_module = config['clusters'][cluster_name]['modules']['kinesis']['streams']
    shard_level_metrics = kinesis_module.get('shard_level_metrics', [])
    stream_name = kinesis_module.get('stream_name', f'{prefix}_{cluster_name}_streamalert')

    module_name = f'kinesis_{cluster_name}'
    cluster_dict['module'][module_name] = {
        'source': './modules/tf_kinesis_streams',
        'account_id': config['global']['account']['aws_account_id'],
        # Lambda event source mappings do not support streams in other regions,
        # so force this to be the same region that all other resources exist in
        # NOTE: Fully regional clusters should be implemented at some point:
        #  https://github.com/airbnb/streamalert/issues/418
        'region': config['global']['account']['region'],
        'cluster': cluster_name,
        'prefix': config['global']['account']['prefix'],
        'stream_name': stream_name,
        'shard_level_metrics': shard_level_metrics,
        'shards': kinesis_module['shards'],
        'retention': kinesis_module['retention'],
        'create_user': kinesis_module.get('create_user', True),
        'trusted_accounts': kinesis_module.get('trusted_accounts', [])
    }

    if outputs := kinesis_module.get('terraform_outputs'):
        generate_tf_outputs(cluster_dict, module_name, outputs)

    return True

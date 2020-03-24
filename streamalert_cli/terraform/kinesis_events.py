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


def generate_kinesis_events(cluster_name, cluster_dict, config):
    """Add the Kinesis Events module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for
                                    a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the kinesis_events module
    """
    cluster_config = config['clusters'][cluster_name]['modules']
    kinesis_events_enabled = bool(cluster_config['kinesis_events']['enabled'])
    batch_size = cluster_config['kinesis_events'].get('batch_size', 100)

    # Kinesis events module
    cluster_dict['module']['kinesis_events_{}'.format(cluster_name)] = {
        'source': './modules/tf_kinesis_events',
        'batch_size': batch_size,
        'lambda_production_enabled': kinesis_events_enabled,
        'lambda_role_id': '${{module.classifier_{}_lambda.role_id}}'.format(cluster_name),
        'lambda_function_alias_arn': '${{module.classifier_{}_lambda.function_alias_arn}}'.format(
            cluster_name
        ),
        'kinesis_stream_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
    }

    return True

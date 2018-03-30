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

from stream_alert_cli.terraform.lambda_module import generate_lambda


def generate_app_integrations(cluster_name, cluster_dict, config):
    """Add the app integrations module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for
                                    a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the app integration module
    """
    prefix = config['global']['account']['prefix']

    for function_name, app_info in config['clusters'][cluster_name] \
        ['modules'].get('stream_alert_apps', {}).iteritems():
        func_prefix = function_name.rstrip('_app')

        module_prefix = 'app_{}_{}'.format(app_info['app_name'], cluster_name)

        config_param = json.dumps({'type': app_info['type'],
                                   'app_name': app_info['app_name'],
                                   'prefix': prefix,
                                   'cluster': cluster_name,
                                   'schedule_expression': app_info['schedule_expression']})

        # Format the iam module with 'app_<app_name_<cluster>_iam'
        cluster_dict['module']['{}_iam'.format(module_prefix)] = {
            'account_id': config['global']['account']['aws_account_id'],
            'app_config_parameter': config_param,
            'cluster': cluster_name,
            'function_prefix': func_prefix,
            'prefix': prefix,
            'region': config['global']['account']['region'],
            'role_id': '${{module.{}_lambda.role_id}}'.format(module_prefix),
            'source': 'modules/tf_stream_alert_app_iam',
            'type': app_info['type']
        }

        # Format the lambda module with 'app_<app_name_<cluster>_lambda'
        cluster_dict['module']['{}_lambda'.format(module_prefix)] = generate_lambda(
            '{}_app'.format(func_prefix),
            config['clusters'][cluster_name]['modules']['stream_alert_apps'][function_name],
            config
        )

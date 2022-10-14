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
from streamalert_cli.terraform.lambda_module import generate_lambda


def generate_apps(cluster_name, cluster_dict, config):
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

    for function_name, app_info in config['clusters'][cluster_name]['modules'].get(
            'streamalert_apps', {}).items():

        tf_module_prefix = f"app_{app_info['app_name']}_{cluster_name}"

        destination_func = f'{prefix}_{cluster_name}_streamalert_classifier'

        app_config = {
            'app_type': app_info['type'],
            'destination_function_name': destination_func,
            'schedule_expression': app_info['schedule_expression']
        }

        # Format the iam module with 'app_<app_name_<cluster>_iam'
        cluster_dict['module'][f'{tf_module_prefix}_iam'] = {
            'account_id': config['global']['account']['aws_account_id'],
            'destination_function_name': destination_func,
            'function_name': function_name,
            'region': config['global']['account']['region'],
            'function_role_id': f'${{module.{tf_module_prefix}_lambda.role_id}}',
            'source': './modules/tf_app_iam'
        }

        # Format the lambda module with 'app_<app_name_<cluster>_lambda'
        cluster_dict['module'][f'{tf_module_prefix}_lambda'] = generate_lambda(
            function_name,
            'streamalert.apps.main.handler',
            config['clusters'][cluster_name]['modules']['streamalert_apps'][function_name],
            config,
            input_event=app_config,
            include_layers=True,
        )

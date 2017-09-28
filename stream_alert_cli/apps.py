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

import boto3
from botocore.exceptions import ClientError

from app_integrations.config import AppConfig
from stream_alert_cli.helpers import continue_prompt, user_input
from stream_alert_cli.logger import LOGGER_CLI


def save_parameter(region, name, value, description, force_overwrite=False):
    """Function to save the designated value to parameter store

    Args:
        name (str): Name of the parameter being saved
        value (str): Value to be saved to the parameter store
    """
    ssm_client = boto3.client('ssm', region_name=region)

    param_value = json.dumps(value)
    # The name of the parameter should follow the format of:
    # <function_name>_<type> where <type> is one of {'auth', 'config', 'state'}
    # and <function_name> follows the the format:
    # '<prefix>_<cluster>_<service>_<app_name>_app'
    # Example: prefix_prod_duo_auth_production_collector_app_config
    def save(overwrite=False):

        ssm_client.put_parameter(
            Name=name,
            Description=description,
            Value=param_value,
            Type='SecureString',
            Overwrite=overwrite
        )

    try:
        save(overwrite=force_overwrite)
    except ClientError as err:
        if err.response['Error']['Code'] == 'ExpiredTokenException':
            # Log an error if this response was due to no credentials being found
            LOGGER_CLI.error('Could not save \'%s\' to parameter store because no '
                             'valid credentials were loaded.', name)

        if err.response['Error']['Code'] != 'ParameterAlreadyExists':
            raise

        prompt = ('A parameter already exists with name \'{}\'. Would you like '
                  'to overwrite the existing value?'.format(name))

        # Ask to overwrite
        if not continue_prompt(message=prompt):
            return False

        save(overwrite=True)

    return True

def save_app_auth_info(app, info, overwrite=False):
    """Function to add app auth information to parameter store

    Args:
        info (dict): Required values needed to save the requested authentication
            information to AWS Parameter Store
    """
    # Get all of the required authentication values from the user for this app integration
    auth_dict = {auth_key: user_input(info['description'], False, info['format'])
                 for auth_key, info in app.required_auth_info().iteritems()}

    description = ('Required authentication information for the \'{}\' service for '
                   'use in the \'{}\' app'.format(info['type'], info['app_name']))

    # Save these to the parameter store
    param_name = '{}_{}'.format(info['function_name'], AppConfig.AUTH_CONFIG_SUFFIX)
    saved = save_parameter(info['region'], param_name, auth_dict, description, overwrite)
    if saved:
        LOGGER_CLI.info('App authentication info successfully saved to parameter store.')
    else:
        LOGGER_CLI.error('App authentication info was not saved to parameter store.')

    return saved

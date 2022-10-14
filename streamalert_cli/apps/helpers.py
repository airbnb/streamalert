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
from streamalert.apps.config import AppConfig
from streamalert.shared.logger import get_logger
from streamalert_cli.helpers import save_parameter, user_input

LOGGER = get_logger(__name__)


def save_app_auth_info(app, info, func_name, overwrite=False):
    """Function to add app auth information to parameter store

    Args:
        info (dict): Required values needed to save the requested authentication
            information to AWS Parameter Store
    """
    # Get all of the required authentication values from the user for this app integration
    auth_dict = {
        auth_key: user_input(info['description'], False, info['format'])
        for auth_key, info in app.required_auth_info().items()
    }

    description = f"Required authentication information for the \'{info['type']}\' service for use in the \'{info['app_name']}\' app"

    # Save these to the parameter store
    param_name = f'{func_name}_{AppConfig.AUTH_CONFIG_SUFFIX}'
    saved = save_parameter(info['region'], param_name, auth_dict, description, overwrite)
    if saved:
        LOGGER.info('App authentication info successfully saved to parameter store.')
    else:
        LOGGER.error('App authentication info was not saved to parameter store.')

    return saved

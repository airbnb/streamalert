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
from getpass import getpass
import json
import os
import re
import subprocess

import boto3
from botocore.exceptions import ClientError

from stream_alert.shared.logger import get_logger

LOGGER = get_logger(__name__)

SCHEMA_TYPE_LOOKUP = {
    bool: 'boolean',
    float: 'float',
    int: 'integer',
    str: 'string',
    dict: dict(),
    list: list()
}


def run_command(runner_args, **kwargs):
    """Helper function to run commands with error handling.

    Args:
        runner_args (list): Commands to run via subprocess
        kwargs:
            cwd (str): A path to execute commands from
            error_message (str): Message to show if command fails
            quiet (bool): Whether to show command output or hide it

    """
    default_error_message = "An error occurred while running: {}".format(' '.join(runner_args))
    error_message = kwargs.get('error_message', default_error_message)
    default_cwd = 'terraform'
    cwd = kwargs.get('cwd', default_cwd)

    # Add the -force-copy flag for s3 state copying to suppress dialogs that
    # the user must type 'yes' into.
    if runner_args[0] == 'terraform':
        if runner_args[1] == 'init':
            runner_args.append('-force-copy')

    stdout_option = None
    if kwargs.get('quiet'):
        stdout_option = open(os.devnull, 'w')

    try:
        subprocess.check_call(runner_args, stdout=stdout_option, cwd=cwd)  # nosec
    except subprocess.CalledProcessError as err:
        LOGGER.error('%s\n%s', error_message, err.cmd)
        return False
    except OSError as err:
        LOGGER.error('%s\n%s (%s)', error_message, err.strerror, runner_args[0])
        return False

    return True


def continue_prompt(message=''):
    """Continue prompt to verify that a user wants to continue or not.

    This prompt's purpose is to prevent accidental changes
    that are difficult to reverse.

    Keyword Args:
        message (str): The message to display to the user

    Returns:
        bool: If the user wants to continue or not
    """
    required_responses = {'yes', 'no'}
    message = message or 'Would you like to continue?'

    response = ''
    while response not in required_responses:
        response = raw_input('\n{} (yes or no): '.format(message))

    return response == 'yes'


def tf_runner(action='apply', refresh=True, auto_approve=False, targets=None):
    """Terraform wrapper to build StreamAlert infrastructure.

    Resolves modules with `terraform get` before continuing.

    Args:
        action (str): Terraform action ('apply' or 'destroy').
        refresh (bool): If True, Terraform will refresh its state before applying the change.
        auto_approve (bool): If True, Terraform will *not* prompt the user for approval.
        targets (list): Optional list of affected targets.
            If not specified, Terraform will run against all of its resources.

    Returns:
        bool: True if the terraform command was successful
    """
    LOGGER.debug('Resolving Terraform modules')
    if not run_command(['terraform', 'get'], quiet=True):
        return False

    tf_command = ['terraform', action, '-refresh={}'.format(str(refresh).lower())]

    if action == 'destroy':
        # Terraform destroy has a '-force' flag instead of '-auto-approve'
        LOGGER.info('Destroying infrastructure')
        tf_command.append('-force={}'.format(str(auto_approve).lower()))
    else:
        LOGGER.info('%s changes', 'Applying' if auto_approve else 'Planning')
        tf_command.append('-auto-approve={}'.format(str(auto_approve).lower()))

    if targets:
        tf_command.extend('-target={}'.format(x) for x in targets)

    return run_command(tf_command)


def check_credentials():
    """Check for valid AWS credentials in environment variables

    Returns:
        bool: True any of the AWS env variables exist
    """
    aws_env_variables = [
        'AWS_PROFILE', 'AWS_SHARED_CREDENTIALS_FILE', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'
    ]
    env_vars_exist = any([env_var in os.environ for env_var in aws_env_variables])

    if not env_vars_exist:
        LOGGER.error('No valid AWS Credentials found in your environment!')
        LOGGER.error('Please follow the setup instructions here: '
                     'https://www.streamalert.io/account.html')
        return False

    return True


def user_input(requested_info, mask, input_restrictions):
    """Prompt user for requested information

    Args:
        requested_info (str): Description of the information needed
        mask (bool): Decides whether to mask input or not

    Returns:
        str: response provided by the user
    """
    # pylint: disable=protected-access
    response = ''
    prompt = '\nPlease supply {}: '.format(requested_info)

    if not mask:
        while not response:
            response = raw_input(prompt)

        # Restrict having spaces or colons in items (applies to things like
        # descriptors, etc)
        if isinstance(input_restrictions, re._pattern_type):
            valid_response = input_restrictions.match(response)
            if not valid_response:
                LOGGER.error('The supplied input should match the following '
                             'regular expression: %s', input_restrictions.pattern)
        elif callable(input_restrictions):
            # Functions can be passed here to perform complex validation of input
            # Transform the response with the validating function
            response = input_restrictions(response)
            valid_response = response is not None and response is not False
            if not valid_response:
                LOGGER.error('The supplied input failed to pass the validation '
                             'function: %s', input_restrictions.__doc__)
        else:
            valid_response = not any(x in input_restrictions for x in response)
            if not valid_response:
                restrictions = ', '.join(
                    '\'{}\''.format(restriction) for restriction in input_restrictions)
                LOGGER.error('The supplied input should not contain any of the following: %s',
                             restrictions)

        if not valid_response:
            return user_input(requested_info, mask, input_restrictions)
    else:
        while not response:
            response = getpass(prompt=prompt)

    return response


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
            LOGGER.error('Could not save \'%s\' to parameter store because no '
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


def record_to_schema(record, recursive=False):
    """Take a record and return a schema that corresponds to it's keys/value types

    This generates a log schema that is compatible with schemas in conf/logs.json

    Args:
        record (dict): The record to generate a schema for
        recursive (bool): True if sub-dictionaries should be recursed

    Returns:
        dict: A new record that reflects the original keys with values that reflect
            the types of the original values
    """
    if not isinstance(record, dict):
        return

    result = {}
    for key, value in record.iteritems():
        # only worry about recursion for dicts, not lists
        if recursive and isinstance(value, dict):
            result[key] = record_to_schema(value, recursive)
        else:
            result[key] = SCHEMA_TYPE_LOOKUP.get(type(value), 'string')

    return result

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
import boto3
from botocore.exceptions import ClientError

from streamalert.shared.logger import get_logger
from streamalert_cli.terraform.generate import terraform_generate_handler
from streamalert_cli.utils import (CLICommand, add_default_lambda_args,
                                   function_map, set_parser_epilog)

LOGGER = get_logger(__name__)


def _rollback_production(lambda_client, function_name):
    """Rollback the production alias for the given function name.

    Args:
        lambda_client (boto3.client): boto3 client to use for rolling back the function
        function_name (str): Name of function to be rolled back

    Returns:
        bool: False if errors occurred, True otherwise
    """
    version = lambda_client.get_alias(FunctionName=function_name,
                                      Name='production')['FunctionVersion']

    if version == '$LATEST':
        # This won't happen with Terraform, but the alias could have been manually changed.
        LOGGER.error('%s:production is pointing to $LATEST instead of a published version',
                     function_name)
        return False

    current_version = int(version)
    if current_version == 1:
        LOGGER.warning('%s:production is already at version 1', function_name)
        return False

    LOGGER.info('Rolling back %s:production from version %d => %d', function_name, current_version,
                current_version - 1)
    try:
        lambda_client.update_alias(FunctionName=function_name,
                                   Name='production',
                                   FunctionVersion=str(current_version - 1))
    except ClientError:
        LOGGER.exception('version not updated')
        return False

    return True


class RollbackCommand(CLICommand):
    description = 'Rollback the specified AWS Lambda function(s)'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the rollback subparser: manage.py rollback [options]"""
        set_parser_epilog(subparser,
                          epilog=('''\
                Example:

                    manage.py rollback --function rule
                '''))

        add_default_lambda_args(subparser)

    @classmethod
    def handler(cls, options, config):
        """Rollback the current production Lambda version(s) by 1.

        Args:
            options: Argparse parsed options
            config (dict): Parsed configuration from conf/

        Returns:
            bool: False if errors occurred, True otherwise
        """
        # Make sure the Terraform code is up to date
        if not terraform_generate_handler(config=config):
            return False

        functions = function_map()
        targeted_funcs = set(options.functions)
        functions = {key: value for key, value in functions.items() if key in targeted_funcs}

        LOGGER.info('Rolling back: %s', ', '.join(sorted(functions)))

        prefix = config['global']['account']['prefix']
        clusters = sorted(options.clusters or config.clusters())
        client = boto3.client('lambda')

        # Track the success of rolling back the functions
        success = True
        for func, suffix in functions.items():
            if suffix:  # A suffix implies this is a standard function naming convention
                success = success and _rollback_production(client, f'{prefix}_streamalert_{suffix}')

            elif func == 'apps':  # Apps need special handling due to unique naming
                for cluster in clusters:
                    cluster_modules = config['clusters'][cluster]['modules']
                    apps_config = cluster_modules.get('streamalert_apps', {})
                    for lambda_name in sorted(apps_config):
                        success = success and _rollback_production(client, lambda_name)
            elif func == 'classifier':  # Classifers need special handling due to clustering
                for cluster in clusters:
                    success = success and _rollback_production(
                        client, f'{prefix}_{cluster}_streamalert_{func}')

        return success

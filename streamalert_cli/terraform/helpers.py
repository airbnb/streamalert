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
from streamalert.shared.logger import get_logger
from streamalert_cli.helpers import run_command
from streamalert_cli.manage_lambda import package

LOGGER = get_logger(__name__)


def terraform_runner(config, refresh=True, auto_approve=False, targets=None, destroy=False):
    """Terraform wrapper to build StreamAlert infrastructure.

    Resolves modules with `terraform get` before continuing.

    Args:
        config (CLIConfig): Loaded StreamAlert config
        action (str): Terraform action ('apply' or 'destroy').
        refresh (bool): If True, Terraform will refresh its state before applying the change.
        auto_approve (bool): If True, Terraform will *not* prompt the user for approval.
        targets (list): Optional list of affected targets.
            If not specified, Terraform will run against all of its resources.

    Returns:
        bool: True if the terraform command was successful
    """
    LOGGER.info('Initializing StreamAlert')
    if not run_command(['terraform', 'init'], cwd=config.build_directory):
        return False

    LOGGER.debug('Resolving Terraform modules')
    if not run_command(['terraform', 'get'], cwd=config.build_directory, quiet=True):
        return False

    tf_command = ['terraform']

    if destroy:
        tf_command.append('destroy')
        # Terraform destroy has a '-force' flag instead of '-auto-approve'
        LOGGER.info('Destroying infrastructure')
        tf_command.append(f'-force={str(auto_approve).lower()}')
    else:
        tf_command.append('apply')
        LOGGER.info('%s changes', 'Applying' if auto_approve else 'Planning')
        tf_command.append(f'-auto-approve={str(auto_approve).lower()}')

    tf_command.append(f'-refresh={str(refresh).lower()}')

    if targets:
        tf_command.extend(f'-target={x}' for x in targets)

    # Build the deployment package so the Lambda does not produce an error
    # TODO: maybe remove this as packaging improvements progress
    deployment_package = package.LambdaPackage(config)
    package_path = deployment_package.create()
    return run_command(tf_command, cwd=config.build_directory) if package_path else False


def terraform_check():
    """Verify that Terraform is configured correctly

    Returns:
        bool: Success or failure of the command ran
    """
    error_message = ('Terraform not found! Please install and add to your $PATH:\n'
                     '\texport PATH=$PATH:/usr/local/terraform/bin')
    return run_command(
        ['terraform', 'version'],
        error_message=error_message,
        quiet=True,
    )

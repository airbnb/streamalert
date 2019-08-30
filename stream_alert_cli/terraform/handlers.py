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
from fnmatch import fnmatch
import json
import os
import shutil

from stream_alert.shared.logger import get_logger
from stream_alert_cli.athena.handler import create_table
from stream_alert_cli.helpers import check_credentials, continue_prompt, run_command, tf_runner
from stream_alert_cli.manage_lambda.deploy import deploy
from stream_alert_cli.terraform.generate import terraform_generate_handler
from stream_alert_cli.terraform.helpers import terraform_check
from stream_alert_cli.utils import CliCommand, set_parser_epilog, UniqueSetAction, add_clusters_arg

LOGGER = get_logger(__name__)


def _terraform_init_backend():
    """Initialize the infrastructure backend (S3) using Terraform

    Returns:
        bool: False if errors occurred, True otherwise
    """
    # Check for valid credentials
    if not check_credentials():
        return False

    # Verify terraform is installed
    if not terraform_check():
        return False

    LOGGER.info('Initializing StreamAlert backend')
    return run_command(['terraform', 'init'])


def terraform_init(options, config):
    """Initialize infrastructure using Terraform

    Args:
        config (CLIConfig): Loaded StreamAlert config

    Returns:
        bool: False if errors occurred, True otherwise
    """
    # Stop here if only initializing the backend
    if options.backend:
        return _terraform_init_backend()

    LOGGER.info('Initializing StreamAlert')

    # generate init Terraform files
    if not terraform_generate_handler(config=config, init=True):
        return False

    LOGGER.info('Initializing Terraform')
    if not run_command(['terraform', 'init']):
        return False

    # build init infrastructure
    LOGGER.info('Building initial infrastructure')
    init_targets = [
        'aws_s3_bucket.lambda_source', 'aws_s3_bucket.logging_bucket',
        'aws_s3_bucket.stream_alert_secrets', 'aws_s3_bucket.terraform_remote_state',
        'aws_s3_bucket.streamalerts',
        'aws_kms_key.server_side_encryption', 'aws_kms_alias.server_side_encryption',
        'aws_kms_key.stream_alert_secrets', 'aws_kms_alias.stream_alert_secrets'
    ]
    if not tf_runner(targets=init_targets):
        LOGGER.error('An error occurred while running StreamAlert init')
        return False

    # generate the main.tf with remote state enabled
    LOGGER.info('Configuring Terraform Remote State')
    if not terraform_generate_handler(config=config, check_tf=False, check_creds=False):
        return False

    if not run_command(['terraform', 'init']):
        return False

    LOGGER.info('Deploying Lambda Functions')

    functions = ['rule', 'alert', 'alert_merger', 'athena', 'classifier']

    deploy(functions, config)

    # we need to manually create the streamalerts table since terraform does not support this
    # See: https://github.com/terraform-providers/terraform-provider-aws/issues/1486
    alerts_bucket = '{}.streamalerts'.format(config['global']['account']['prefix'])
    create_table('alerts', alerts_bucket, config)

    LOGGER.info('Building remainding infrastructure')
    return tf_runner(refresh=False)



class TerraformBuildCommand(CliCommand):
    description = 'Run terraform against StreamAlert modules, optionally targeting specific modules'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add build subparser: manage.py build [options]"""
        set_parser_epilog(
            subparser,
            epilog=(
                '''\
                Example:

                    manage.py build --target alert_processor_lambda
                '''
            )
        )

        _add_default_tf_args(subparser)

    @classmethod
    def handler(cls, options, config):
        """Run Terraform with an optional set of targets and clusters

        Args:
            options (argparse.Namespace): Parsed arguments from manage.py
            config (CLIConfig): Loaded StreamAlert config

        Returns:
            bool: False if errors occurred, True otherwise
        """
        if not terraform_generate_handler(config=config):
            return False

        target_modules, valid = _get_valid_tf_targets(config, options.target)
        if not valid:
            return False

        return tf_runner(targets=target_modules if target_modules else None)


def _add_default_tf_args(tf_parser):
    """Add the default terraform parser options"""
    tf_parser.add_argument(
        '-t',
        '--target',
        metavar='TARGET',
        help=(
            'One or more Terraform module name to target. Use `list-targets` for a list '
            'of available targets'
        ),
        action=UniqueSetAction,
        default=set(),
        nargs='+'
    )

    # Add the option to specify cluster(s)
    add_clusters_arg(tf_parser)


def terraform_destroy_handler(options, config):
    """Use Terraform to destroy any existing infrastructure

    Args:
        options (argparse.Namespace): Parsed arguments from manage.py
        config (CLIConfig): Loaded StreamAlert config

    Returns:
        bool: False if errors occurred, True otherwise
    """
    # Check for valid credentials
    if not check_credentials():
        return False

    # Verify terraform is installed
    if not terraform_check():
        return False

    # Ask for approval here since multiple Terraform commands may be necessary
    if not continue_prompt(message='Are you sure you want to destroy?'):
        return False

    if options.target:
        target_modules, valid = _get_valid_tf_targets(config, options.target)
        if not valid:
            return False

        return tf_runner(
            action='destroy',
            auto_approve=True,
            targets=target_modules if target_modules else None
        )

    # Migrate back to local state so Terraform can successfully
    # destroy the S3 bucket used by the backend.
    # Do not check for terraform or aws creds again since these were checked above
    if not terraform_generate_handler(config=config, init=True, check_tf=False, check_creds=False):
        return False

    if not run_command(['terraform', 'init']):
        return False

    # Destroy all of the infrastructure
    if not tf_runner(action='destroy', auto_approve=True):
        return False

    # Remove old Terraform files
    return TerraformCleanCommand.handler(options, config)


class TerraformCleanCommand(CliCommand):
    description = 'Remove current Terraform files'

    @classmethod
    def setup_subparser(cls, subparser):
        """Manage.py clean takes no arguments"""

    @classmethod
    def handler(cls, options, config):
        """Remove leftover Terraform statefiles and main/cluster files

        Args:
            config (CLIConfig): Loaded StreamAlert config

        Returns:
            bool: False if errors occurred, True otherwise
        """
        LOGGER.info('Cleaning Terraform files')

        def _rm_file(path):
            if not os.path.isfile(path):
                return
            print('Removing terraform file: {}'.format(path))
            os.remove(path)

        for root, _, files in os.walk('terraform'):
            for file_name in files:
                path = os.path.join(root, file_name)
                if path.endswith('.tf.json'):
                    _rm_file(path)

        for tf_file in ['terraform.tfstate', 'terraform.tfstate.backup']:
            path = 'terraform/{}'.format(tf_file)
            _rm_file(path)

        # Finally, delete the Terraform directory
        if os.path.isdir('terraform/.terraform/'):
            shutil.rmtree('terraform/.terraform/')

        return True


def _get_valid_tf_targets(config, targets):
    all_matches = set()
    if not targets:
        return all_matches, True  # Empty targets is acceptable

    modules = get_tf_modules(config)
    if not modules:
        return all_matches, False

    for target in targets:
        matches = {
            '{}.{}'.format(value_type, value)
            for value_type, values in modules.items()
            for value in values
            if fnmatch(value, target)
        }
        if not matches:
            LOGGER.error('Invalid terraform target supplied: %s', target)
            continue
        all_matches.update(matches)

    if not all_matches:
        LOGGER.error(
            'No terraform targets found matching supplied target(s): %s',
            ', '.join(sorted(targets))
        )
        return all_matches, False

    return all_matches, True


def get_tf_modules(config, generate=False):
    if generate:
        if not terraform_generate_handler(config=config, check_tf=False, check_creds=False):
            return False

    modules = set()
    resources = set()
    for root, _, files in os.walk('terraform'):
        for file_name in files:
            path = os.path.join(root, file_name)
            if path.endswith('.tf.json'):
                with open(path, 'r') as tf_file:
                    tf_data = json.load(tf_file)
                    modules.update(set((tf_data['module'])))
                    resources.update(
                        '{}.{}'.format(resource, value)
                        for resource, values in tf_data.get('resource', {}).items()
                        for value in values
                    )

    return {'module': modules, 'resource': resources}


def terraform_list_targets(config):
    """Print the available terraform targets

    Args:
        config (CLIConfig): Loaded StreamAlert config

    Returns:
        bool: False if errors occurred, True otherwise
    """
    modules = get_tf_modules(config, True)
    if not modules:
        return False

    max_resource_len = max(len(value) for values in modules.values() for value in values) + 8

    row_format_str = '{prefix:<{pad}}{value}'

    header = row_format_str.format(prefix='Target', pad=max_resource_len, value='Type')
    print(header)
    print('-' * (len(header) + 4))
    for value_type in sorted(modules):
        for item in sorted(modules[value_type]):
            print(row_format_str.format(prefix=item, pad=max_resource_len, value=value_type))

    return True

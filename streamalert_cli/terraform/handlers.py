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
import json
import os
from fnmatch import fnmatch

from streamalert.shared.config import firehose_alerts_bucket
from streamalert.shared.logger import get_logger
from streamalert.shared.utils import get_data_file_format
from streamalert_cli.athena.handler import create_log_tables, create_table
from streamalert_cli.helpers import (check_credentials, continue_prompt,
                                     run_command)
from streamalert_cli.manage_lambda.deploy import deploy
from streamalert_cli.terraform.generate import terraform_generate_handler
from streamalert_cli.terraform.helpers import terraform_check, terraform_runner
from streamalert_cli.utils import (CLICommand, UniqueSortedListAction,
                                   add_clusters_arg, set_parser_epilog)

LOGGER = get_logger(__name__)


class TerraformInitCommand(CLICommand):
    description = 'Initialize StreamAlert infrastructure'

    @classmethod
    def setup_subparser(cls, subparser):
        """Manage.py init takes no arguments"""

    @classmethod
    def handler(cls, options, config):
        """Initialize infrastructure using Terraform

        Args:
            config (CLIConfig): Loaded StreamAlert config

        Returns:
            bool: False if errors occurred, True otherwise
        """
        LOGGER.info('Initializing StreamAlert')

        # generate init Terraform files
        if not terraform_generate_handler(config=config, init=True):
            return False

        LOGGER.info('Initializing Terraform')
        if not run_command(['terraform', 'init'], cwd=config.build_directory):
            return False

        # build init infrastructure
        LOGGER.info('Building initial infrastructure')
        init_targets = [
            'aws_s3_bucket.lambda_source',
            'aws_s3_bucket.logging_bucket',
            'aws_s3_bucket.streamalert_secrets',
            'aws_s3_bucket.terraform_remote_state',
            'aws_s3_bucket.streamalerts',
            'aws_kms_key.server_side_encryption',
            'aws_kms_alias.server_side_encryption',
            'aws_kms_key.streamalert_secrets',
            'aws_kms_alias.streamalert_secrets',
            'module.streamalert_athena',  # required for the alerts table
            'aws_dynamodb_table.terraform_remote_state_lock'
        ]

        # this bucket must exist before the log tables can be created, but
        # shouldn't be created unless the firehose is enabled
        if config['global']['infrastructure'].get('firehose', {}).get('enabled'):
            init_targets.append('aws_s3_bucket.streamalert_data')

        if not terraform_runner(config, targets=init_targets):
            LOGGER.error('An error occurred while running StreamAlert init')
            return False

        # generate the main.tf with remote state enabled
        LOGGER.info('Configuring Terraform Remote State')
        if not terraform_generate_handler(config=config, check_tf=False, check_creds=False):
            return False

        if not run_command(['terraform', 'init'], cwd=config.build_directory):
            return False

        LOGGER.info('Deploying Lambda Functions')

        functions = ['rule', 'alert', 'alert_merger', 'athena', 'classifier']

        deploy(config, functions)

        # we need to manually create the streamalerts table since terraform does not support this
        # See: https://github.com/terraform-providers/terraform-provider-aws/issues/1486
        if get_data_file_format(config) == 'json':
            # Terraform v0.12 now supports creating Athena tables. We will support
            # to use terraform aws_glue_catalog_table resource to create table only
            # when data file_format is set to "parquet" in "athena_partitioner_config"
            #
            # For "json" file_format, we will continue using Athena DDL query to
            # create tables. However, this capabity will be faded out in the future
            # release because we want users to take advantage of parquet performance.
            alerts_bucket = firehose_alerts_bucket(config)
            create_table('alerts', alerts_bucket, config)

            # Create the glue catalog tables for the enabled logs
            if not create_log_tables(config=config):
                return

        LOGGER.info('Building remaining infrastructure')
        return terraform_runner(config, refresh=False)


class TerraformBuildCommand(CLICommand):
    description = 'Run terraform against StreamAlert modules, optionally targeting specific modules'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add build subparser: manage.py build [options]"""
        set_parser_epilog(subparser,
                          epilog=('''\
                Example:

                    manage.py build --target alert_processor_lambda
                '''))

        _add_default_tf_args(subparser, add_cluster_args=False)

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

        # Will create log tables only when file_format set to "json" and return erlier if
        # log tables creation failed.
        # This capabity will be faded out in the future release.
        if get_data_file_format(config) == 'json' and not create_log_tables(config=config):
            return

        target_modules, valid = _get_valid_tf_targets(config, options.target)
        return terraform_runner(config, targets=target_modules or None) if valid else False


class TerraformDestroyCommand(CLICommand):
    description = 'Destroy StreamAlert infrastructure, optionally targeting specific modules'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add destroy subparser: manage.py destroy [options]"""
        set_parser_epilog(subparser,
                          epilog=('''\
                Example:

                    manage.py destroy --target aws_s3_bucket-streamalerts
                '''))

        _add_default_tf_args(subparser)

    @classmethod
    def handler(cls, options, config):
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
            return terraform_runner(
                config, destroy=True, auto_approve=True, targets=target_modules
                or None) if valid else False

        # Migrate back to local state so Terraform can successfully
        # destroy the S3 bucket used by the backend.
        # Do not check for terraform or aws creds again since these were checked above
        if not terraform_generate_handler(
                config=config, init=True, check_tf=False, check_creds=False):
            return False

        return terraform_runner(config, destroy=True, auto_approve=True) if run_command(
            ['terraform', 'init'], cwd=config.build_directory) else False


class TerraformListTargetsCommand(CLICommand):
    description = 'List available Terraform modules to be used for targeted builds'

    @classmethod
    def setup_subparser(cls, subparser):
        """Manage.py list-targets does not take any arguments"""

    @classmethod
    def handler(cls, options, config):
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


def _add_default_tf_args(tf_parser, add_cluster_args=True):
    """Add the default terraform parser options"""
    tf_parser.add_argument(
        '-t',
        '--target',
        metavar='TARGET',
        help=('One or more Terraform module name to target. Use `list-targets` for a list '
              'of available targets'),
        action=UniqueSortedListAction,
        default=[],
        nargs='+')

    if add_cluster_args:
        # Add the option to specify cluster(s)
        add_clusters_arg(tf_parser)


def _get_valid_tf_targets(config, targets):
    all_matches = set()
    if not targets:
        return all_matches, True  # Empty targets is acceptable

    modules = get_tf_modules(config)
    if not modules:
        return all_matches, False

    for target in targets:
        matches = {
            f'{value_type}.{value}' if value_type == 'module' else value
            for value_type, values in modules.items() for value in values if fnmatch(value, target)
        }

        if not matches:
            LOGGER.error('Invalid terraform target supplied: %s', target)
            continue
        all_matches.update(matches)

    if not all_matches:
        LOGGER.error('No terraform targets found matching supplied target(s): %s',
                     ', '.join(sorted(targets)))
        return all_matches, False

    return all_matches, True


def get_tf_modules(config, generate=False):
    if generate and not terraform_generate_handler(config=config, check_tf=False,
                                                   check_creds=False):
        return False

    modules = set()
    resources = set()
    for root, _, files in os.walk(config.build_directory):
        for file_name in files:
            path = os.path.join(root, file_name)
            if path.endswith('.tf.json'):
                with open(path, encoding="utf-8") as tf_file:
                    tf_data = json.load(tf_file)
                    modules.update(set(tf_data['module']))
                    resources.update(f'{resource}.{value}'
                                     for resource, values in tf_data.get('resource', {}).items()
                                     for value in values)

    return {'module': modules, 'resource': resources}

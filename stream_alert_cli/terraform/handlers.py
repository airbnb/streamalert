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
import os
import shutil
import sys

from stream_alert.shared.logger import get_logger
from stream_alert_cli.athena.handler import create_table
from stream_alert_cli.helpers import check_credentials, continue_prompt, run_command, tf_runner
from stream_alert_cli.manage_lambda.deploy import deploy
from stream_alert_cli.terraform.generate import terraform_generate_handler
from stream_alert_cli.terraform.helpers import terraform_check

LOGGER = get_logger(__name__)


def _terraform_init_backend():
    """Initialize the infrastructure backend (S3) using Terraform"""
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
        config (CLIConfig): Loaded StreamAlert CLI
    """
    # Stop here if only initializing the backend
    if options.backend:
        if not _terraform_init_backend():
            sys.exit(1)
        return

    LOGGER.info('Initializing StreamAlert')

    # generate init Terraform files
    if not terraform_generate_handler(config=config, init=True):
        return

    LOGGER.info('Initializing Terraform')
    if not run_command(['terraform', 'init']):
        sys.exit(1)

    # build init infrastructure
    LOGGER.info('Building Initial Infrastructure')
    init_targets = [
        'aws_s3_bucket.lambda_source', 'aws_s3_bucket.logging_bucket',
        'aws_s3_bucket.stream_alert_secrets', 'aws_s3_bucket.terraform_remote_state',
        'aws_s3_bucket.streamalerts',
        'aws_kms_key.server_side_encryption', 'aws_kms_alias.server_side_encryption',
        'aws_kms_key.stream_alert_secrets', 'aws_kms_alias.stream_alert_secrets'
    ]
    if not tf_runner(targets=init_targets):
        LOGGER.error('An error occurred while running StreamAlert init')
        sys.exit(1)

    # generate the main.tf with remote state enabled
    LOGGER.info('Configuring Terraform Remote State')
    if not terraform_generate_handler(config=config, check_tf=False, check_creds=False):
        return

    if not run_command(['terraform', 'init']):
        return

    LOGGER.info('Deploying Lambda Functions')

    processors = ['rule', 'alert', 'alert_merger', 'athena', 'classifier']

    deploy(processors, config)

    # we need to manually create the streamalerts table since terraform does not support this
    # See: https://github.com/terraform-providers/terraform-provider-aws/issues/1486
    alerts_bucket = '{}.streamalerts'.format(config['global']['account']['prefix'])
    create_table('alerts', alerts_bucket, config)

    LOGGER.info('Building remainding infrastructure')
    tf_runner(refresh=False)


def terraform_build_handler(options, config):
    """Run Terraform with an optional set of targets and clusters

    Args:
        options (argparse.Namespace): Parsed arguments from manage.py
        config (CLIConfig): Loaded StreamAlert CLI
    """
    if not terraform_generate_handler(config=config):
        return

    # Define the set of custom targets to apply
    tf_runner_targets = set()
    # If resource are not clustered, it is most likely required to
    # fall in the custom mapping below:
    custom_module_mapping = {
        'athena': 'module.stream_alert_athena',
        'threat_intel_downloader': 'module.threat_intel_downloader'
    }
    clusters = set(options.clusters or config.clusters())

    if options.target:
        tf_runner_targets.update({
            'module.{}_{}'.format(target, cluster)
            for cluster in clusters for target in options.target
        })
        for name in custom_module_mapping:
            if name in options.target:
                tf_runner_targets.add(custom_module_mapping[name])

    tf_runner(targets=tf_runner_targets)


def terraform_destroy_handler(options, config):
    """Use Terraform to destroy any existing infrastructure

    Args:
        options (argparse.Namespace): Parsed arguments from manage.py
        config (CLIConfig): Loaded StreamAlert CLI
    """
    # Check for valid credentials
    if not check_credentials():
        return

    # Verify terraform is installed
    if not terraform_check():
        return

    # Ask for approval here since multiple Terraform commands may be necessary
    if not continue_prompt(message='Are you sure you want to destroy?'):
        sys.exit(1)

    if options.target:
        targets = []
        # Iterate over any targets to destroy. Global modules, like athena
        # are prefixed with `stream_alert_` while cluster based modules
        # are a combination of the target and cluster name
        for target in options.target:
            if target == 'athena':
                targets.append('module.stream_alert_{}'.format(target))
            elif target == 'threat_intel_downloader':
                targets.append('module.threat_intel_downloader')
            else:
                targets.extend(
                    ['module.{}_{}'.format(target, cluster) for cluster in config.clusters()])

        tf_runner(action='destroy', auto_approve=True, targets=targets)
        return

    # Migrate back to local state so Terraform can successfully
    # destroy the S3 bucket used by the backend.
    # Do not check for terraform or aws creds again since these were checked above
    if not terraform_generate_handler(config=config, init=True, check_tf=False, check_creds=False):
        return

    if not run_command(['terraform', 'init']):
        return

    # Destroy all of the infrastructure
    if not tf_runner(action='destroy', auto_approve=True):
        return

    # Remove old Terraform files
    terraform_clean_handler(config)


def terraform_clean_handler(config):
    """Remove leftover Terraform statefiles and main/cluster files

    Args:
        config (CLIConfig): Loaded StreamAlert CLI
    """
    LOGGER.info('Cleaning Terraform files')

    cleanup_files = ['{}.tf.json'.format(cluster) for cluster in config.clusters()]
    cleanup_files.extend(
        ['athena.tf.json', 'main.tf.json', 'terraform.tfstate', 'terraform.tfstate.backup'])
    for tf_file in cleanup_files:
        file_to_remove = 'terraform/{}'.format(tf_file)
        if not os.path.isfile(file_to_remove):
            continue
        os.remove(file_to_remove)

    # Finally, delete the Terraform directory
    if os.path.isdir('terraform/.terraform/'):
        shutil.rmtree('terraform/.terraform/')

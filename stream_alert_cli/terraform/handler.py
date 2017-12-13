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
from collections import namedtuple
import os
import shutil
import sys

from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.helpers import check_credentials, continue_prompt, run_command, tf_runner
from stream_alert_cli.manage_lambda.deploy import deploy
from stream_alert_cli.terraform.generate import terraform_generate


def terraform_check():
    """Verify that Terraform is configured correctly

    Returns:
        bool: Success or failure of the command ran"""
    prereqs_message = ('Terraform not found! Please install and add to '
                       'your $PATH:\n'
                       '\t$ export PATH=$PATH:/usr/local/terraform/bin')
    return run_command(['terraform', 'version'], error_message=prereqs_message, quiet=True)


def terraform_handler(options, config):
    """Handle all Terraform CLI operations

    Args:
        options (namedtuple): Parsed arguments from manage.py
    """
    # Check for valid credentials
    if not check_credentials():
        return

    # Verify terraform is installed
    if not terraform_check():
        return
    # Use a named tuple to match the 'processor' attribute in the argparse options
    deploy_opts = namedtuple('DeployOptions', ['processor', 'clusters'])

    # Plan and Apply our streamalert infrastructure
    if options.subcommand == 'build':
        terraform_build(options, config)

    # generate terraform files
    elif options.subcommand == 'generate':
        if not terraform_generate(config=config):
            return

    elif options.subcommand == 'init-backend':
        run_command(['terraform', 'init'])

    # initialize streamalert infrastructure from a blank state
    elif options.subcommand == 'init':
        LOGGER_CLI.info('Initializing StreamAlert')

        # generate init Terraform files
        if not terraform_generate(config=config, init=True):
            return

        LOGGER_CLI.info('Initializing Terraform')
        if not run_command(['terraform', 'init']):
            sys.exit(1)

        # build init infrastructure
        LOGGER_CLI.info('Building Initial Infrastructure')
        init_targets = [
            'aws_s3_bucket.lambda_source', 'aws_s3_bucket.logging_bucket',
            'aws_s3_bucket.stream_alert_secrets', 'aws_s3_bucket.terraform_remote_state',
            'aws_s3_bucket.streamalerts', 'aws_kms_key.stream_alert_secrets',
            'aws_kms_alias.stream_alert_secrets'
        ]
        if not tf_runner(targets=init_targets):
            LOGGER_CLI.error('An error occured while running StreamAlert init')
            sys.exit(1)

        # generate the main.tf with remote state enabled
        LOGGER_CLI.info('Configuring Terraform Remote State')
        if not terraform_generate(config=config):
            return

        if not run_command(['terraform', 'init']):
            return

        LOGGER_CLI.info('Deploying Lambda Functions')
        # deploy both lambda functions
        deploy(deploy_opts(['rule', 'alert'], []), config)
        # create all remainder infrastructure

        LOGGER_CLI.info('Building Remainder Infrastructure')
        tf_runner()

    elif options.subcommand == 'clean':
        if not continue_prompt(message='Are you sure you want to clean all Terraform files?'):
            sys.exit(1)
        terraform_clean(config)

    elif options.subcommand == 'destroy':
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

            tf_runner(targets=targets, action='destroy')
            return

        # Migrate back to local state so Terraform can successfully
        # destroy the S3 bucket used by the backend.
        if not terraform_generate(config=config, init=True):
            return

        if not run_command(['terraform', 'init']):
            return

        # Destroy all of the infrastructure
        if not tf_runner(action='destroy'):
            return

        # Remove old Terraform files
        terraform_clean(config)

    # get a quick status on our declared infrastructure
    elif options.subcommand == 'status':
        terraform_status(config)


def terraform_build(options, config):
    """Run Terraform with an optional set of targets and clusters

    Args:
        options (namedtuple): Parsed arguments from manage.py
    """
    if not terraform_generate(config=config):
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


def terraform_clean(config):
    """Remove leftover Terraform statefiles and main/cluster files"""
    LOGGER_CLI.info('Cleaning Terraform files')

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


def terraform_status(config):
    """Display current AWS infrastructure built by Terraform"""
    for cluster, region in config['clusters'].items():
        print '\n======== {} ========'.format(cluster)
        print 'Region: {}'.format(region)
        print('Alert Processor Lambda Settings: \n\tTimeout: {}\n\tMemory: {}'
              '\n\tProd Version: {}').format(config['alert_processor_lambda_config'][cluster][0],
                                             config['alert_processor_lambda_config'][cluster][1],
                                             config['alert_processor_versions'][cluster])
        print('Rule Processor Lambda Settings: \n\tTimeout: {}\n\tMemory: {}'
              '\n\tProd Version: {}').format(config['rule_processor_lambda_config'][cluster][0],
                                             config['rule_processor_lambda_config'][cluster][1],
                                             config['rule_processor_versions'][cluster])
        print 'Kinesis settings: \n\tShards: {}\n\tRetention: {}'.format(
            config['kinesis_streams_config'][cluster][0],
            config['kinesis_streams_config'][cluster][1])

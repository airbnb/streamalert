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

from stream_alert_cli.config import CLIConfig
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.helpers import run_command, tf_runner, continue_prompt
from stream_alert_cli.manage_lambda.deploy import deploy
from stream_alert_cli.terraform.generate import terraform_generate


CONFIG = CLIConfig()

def terraform_check():
    """Verify that Terraform is configured correctly

    Returns:
        bool: Success or failure of the command ran"""
    prereqs_message = ('Terraform not found! Please install and add to '
                       'your $PATH:\n'
                       '\t$ export PATH=$PATH:/usr/local/terraform/bin')
    return run_command(['terraform', 'version'],
                       error_message=prereqs_message,
                       quiet=True)

def terraform_handler(options):
    """Handle all Terraform CLI operations

    Args:
        options (namedtuple): Parsed arguments from manage.py
    """
    # Verify terraform is installed
    if not terraform_check():
        return
    # Use a named tuple to match the 'processor' attribute in the argparse options
    deploy_opts = namedtuple('DeployOptions', ['processor'])

    # Plan and Apply our streamalert infrastructure
    if options.subcommand == 'build':
        terraform_build(options)

    # generate terraform files
    elif options.subcommand == 'generate':
        if not terraform_generate(config=CONFIG):
            return

    elif options.subcommand == 'init-backend':
        run_command(['terraform', 'init'])

    # initialize streamalert infrastructure from a blank state
    elif options.subcommand == 'init':
        LOGGER_CLI.info('Initializing StreamAlert')

        # generate init Terraform files
        if not terraform_generate(config=CONFIG, init=True):
            return

        LOGGER_CLI.info('Initializing Terraform')
        if not run_command(['terraform', 'init']):
            sys.exit(1)

        # build init infrastructure
        LOGGER_CLI.info('Building Initial Infrastructure')
        init_targets = [
            'aws_s3_bucket.lambda_source',
            'aws_s3_bucket.logging_bucket',
            'aws_s3_bucket.stream_alert_secrets',
            'aws_s3_bucket.terraform_remote_state',
            'aws_s3_bucket.streamalerts',
            'aws_kms_key.stream_alert_secrets',
            'aws_kms_alias.stream_alert_secrets'
        ]
        if not tf_runner(targets=init_targets):
            LOGGER_CLI.error('An error occured while running StreamAlert init')
            sys.exit(1)

        # generate the main.tf with remote state enabled
        LOGGER_CLI.info('Configuring Terraform Remote State')
        if not terraform_generate(config=CONFIG):
            return

        if not run_command(['terraform', 'init']):
            return

        LOGGER_CLI.info('Deploying Lambda Functions')
        # deploy both lambda functions
        deploy(deploy_opts(['rule', 'alert']))
        # create all remainder infrastructure

        LOGGER_CLI.info('Building Remainder Infrastructure')
        tf_runner()

    elif options.subcommand == 'clean':
        continue_prompt(message='Are you sure you want to clean all Terraform files?')
        terraform_clean()

    elif options.subcommand == 'destroy':
        if options.target:
            targets = []
            # Iterate over any targets to destroy. Global modules, like athena
            # are prefixed with `stream_alert_` while cluster based modules
            # are a combination of the target and cluster name
            for target in options.target:
                if target == 'athena':
                    targets.append('module.stream_alert_{}'.format(target))
                else:
                    targets.extend(['module.{}_{}'.format(target, cluster)
                                    for cluster in CONFIG.clusters()])

            tf_runner(targets=targets, action='destroy')
            return

        # Migrate back to local state so Terraform can successfully
        # destroy the S3 bucket used by the backend.
        if not terraform_generate(config=CONFIG, init=True):
            return

        if not run_command(['terraform', 'init']):
            return

        # Destroy all of the infrastructure
        if not tf_runner(action='destroy'):
            return

        # Remove old Terraform files
        terraform_clean()

    # get a quick status on our declared infrastructure
    elif options.subcommand == 'status':
        terraform_status()

def terraform_build(options):
    """Run Terraform with an optional set of targets

    Args:
        options (namedtuple): Parsed arguments from manage.py
    """
    # Generate Terraform files
    if not terraform_generate(config=CONFIG):
        return
    # Target is for terraforming a specific streamalert module.
    # This value is passed as a list
    if options.target == ['athena']:
        tf_runner(targets=['module.stream_alert_athena'])
    elif options.target:
        targets = ['module.{}_{}'.format(target, cluster)
                   for cluster in CONFIG.clusters()
                   for target in options.target]
        tf_runner(targets=targets)
    else:
        tf_runner()

def terraform_clean():
    """Remove leftover Terraform statefiles and main/cluster files"""
    LOGGER_CLI.info('Cleaning Terraform files')

    cleanup_files = ['{}.tf.json'.format(cluster) for cluster in CONFIG.clusters()]
    cleanup_files.extend([
        'main.tf.json',
        'terraform.tfstate',
        'terraform.tfstate.backup'
    ])
    for tf_file in cleanup_files:
        file_to_remove = 'terraform/{}'.format(tf_file)
        if not os.path.isfile(file_to_remove):
            continue
        os.remove(file_to_remove)

    # Finally, delete the Terraform directory
    if os.path.isdir('terraform/.terraform/'):
        shutil.rmtree('terraform/.terraform/')

def terraform_status():
    """Display current AWS infrastructure built by Terraform"""
    for cluster, region in CONFIG['clusters'].items():
        print '\n======== {} ========'.format(cluster)
        print 'Region: {}'.format(region)
        print ('Alert Processor Lambda Settings: \n\tTimeout: {}\n\tMemory: {}'
               '\n\tProd Version: {}').format(
                   CONFIG['alert_processor_lambda_config'][cluster][0],
                   CONFIG['alert_processor_lambda_config'][cluster][1],
                   CONFIG['alert_processor_versions'][cluster])
        print ('Rule Processor Lambda Settings: \n\tTimeout: {}\n\tMemory: {}'
               '\n\tProd Version: {}').format(
                   CONFIG['rule_processor_lambda_config'][cluster][0],
                   CONFIG['rule_processor_lambda_config'][cluster][1],
                   CONFIG['rule_processor_versions'][cluster])
        print 'Kinesis settings: \n\tShards: {}\n\tRetention: {}'.format(
            CONFIG['kinesis_streams_config'][cluster][0],
            CONFIG['kinesis_streams_config'][cluster][1]
        )

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
from getpass import getpass
import os
import shutil
import sys

from stream_alert import __version__ as current_version
from stream_alert.alert_processor.outputs import get_output_dispatcher
from stream_alert.athena_partition_refresh.main import StreamAlertAthenaClient

from stream_alert_cli import helpers
from stream_alert_cli.config import CLIConfig
from stream_alert_cli.helpers import continue_prompt
from stream_alert_cli.logger import LOGGER_CLI
import stream_alert_cli.outputs as config_outputs
from stream_alert_cli.package import AlertProcessorPackage, AthenaPackage, RuleProcessorPackage
from stream_alert_cli.terraform.generate import terraform_generate
from stream_alert_cli.test import stream_alert_test
from stream_alert_cli.version import LambdaVersion

CONFIG = CLIConfig()


def cli_runner(options):
    """Main Stream Alert CLI handler

    Args:
        options (dict): command line arguments passed from the argparser.
            Contains the following keys for terraform commands:
                (command, subcommand, target)
            Contains the following keys for lambda commands:
                (command, subcommand, env, func, source)
    """
    cli_load_message = ('Issues? Report here: '
                        'https://github.com/airbnb/streamalert/issues')
    LOGGER_CLI.info(cli_load_message)

    if options.debug:
        LOGGER_CLI.setLevel('DEBUG')

    if options.command == 'output':
        configure_output(options)

    elif options.command == 'lambda':
        lambda_handler(options)

    elif options.command == 'live-test':
        stream_alert_test(options, CONFIG)

    elif options.command == 'validate-schemas':
        stream_alert_test(options)

    elif options.command == 'terraform':
        terraform_handler(options)

    elif options.command == 'configure':
        configure_handler(options)

    elif options.command == 'athena':
        athena_handler(options)

    elif options.command == 'metrics':
        _toggle_metrics(options)

    elif options.command == 'create-alarm':
        _create_alarm(options)


def athena_handler(options):
    """Handle Athena operations"""
    athena_client = StreamAlertAthenaClient(CONFIG,
                                            results_key_prefix='stream_alert_cli')

    if options.subcommand == 'init':
        CONFIG.generate_athena()

    elif options.subcommand == 'enable':
        CONFIG.set_athena_lambda_enable()

    elif options.subcommand == 'create-db':
        if athena_client.check_database_exists():
            LOGGER_CLI.info('The \'streamalert\' database already exists, nothing to do')
            return

        create_db_success, create_db_result = athena_client.run_athena_query(
            query='CREATE DATABASE streamalert')

        if create_db_success and create_db_result['ResultSet'].get('Rows'):
            LOGGER_CLI.info('streamalert database successfully created!')
            LOGGER_CLI.info('results: %s', create_db_result['ResultSet']['Rows'])

    elif options.subcommand == 'create-table':
        if options.type == 'alerts':
            if not options.bucket:
                LOGGER_CLI.error('Missing command line argument --bucket')
                return

            if athena_client.check_table_exists(options.type):
                LOGGER_CLI.info('The \'alerts\' table already exists.')
                return

            query = ('CREATE EXTERNAL TABLE alerts ('
                     'log_source string,'
                     'log_type string,'
                     'outputs array<string>,'
                     'record string,'
                     'rule_description string,'
                     'rule_name string,'
                     'source_entity string,'
                     'source_service string)'
                     'PARTITIONED BY (dt string)'
                     'ROW FORMAT SERDE \'org.openx.data.jsonserde.JsonSerDe\''
                     'LOCATION \'s3://{bucket}/alerts/\''.format(bucket=options.bucket))

            create_table_success, _ = athena_client.run_athena_query(
                query=query,
                database='streamalert'
            )

            if create_table_success:
                CONFIG['lambda']['athena_partition_refresh_config'] \
                    ['refresh_type'][options.refresh_type][options.bucket] = 'alerts'
                CONFIG.write()
                LOGGER_CLI.info('The alerts table was successfully created!')


def lambda_handler(options):
    """Handle all Lambda CLI operations"""

    if options.subcommand == 'deploy':
        # Make sure the Terraform code is up to date
        if not terraform_generate(config=CONFIG):
            return
        deploy(options)

    elif options.subcommand == 'rollback':
        # Make sure the Terraform code is up to date
        if not terraform_generate(config=CONFIG):
            return
        rollback(options)

    elif options.subcommand == 'test':
        stream_alert_test(options)


def configure_handler(options):
    """Configure StreamAlert main settings

    Args:
        options (namedtuple): ArgParse command result
    """
    if options.config_key == 'prefix':
        CONFIG.set_prefix(options.config_value)

    elif options.config_key == 'aws_account_id':
        CONFIG.set_aws_account_id(options.config_value)


def terraform_check():
    """Verify that Terraform is configured correctly"""
    prereqs_message = ('Terraform not found! Please install and add to '
                       'your $PATH:\n'
                       '\t$ export PATH=$PATH:/usr/local/terraform/bin')
    return run_command(['terraform', 'version'],
                       error_message=prereqs_message,
                       quiet=True)


def terraform_handler(options):
    """Handle all Terraform CLI operations"""
    # Verify terraform is installed
    if not terraform_check():
        return
    # Use a named tuple to match the 'processor' attribute in the argparse options
    deploy_opts = namedtuple('DeployOptions', ['processor'])

    # Plan and Apply our streamalert infrastructure
    if options.subcommand == 'build':
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
        status()


def terraform_clean():
    """Remove leftover Terraform statefiles and main/cluster files"""
    LOGGER_CLI.info('Cleaning Terraform files')

    cleanup_files = ['{}.tf'.format(cluster) for cluster in CONFIG.clusters()]
    cleanup_files.extend([
        'main.tf',
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


def run_command(args=None, **kwargs):
    """Alias to CLI Helpers.run_command"""
    return helpers.run_command(args, **kwargs)


def tf_runner(**kwargs):
    """Terraform wrapper to build StreamAlert infrastructure.

    Steps:
        - resolve modules with `terraform get`
        - run `terraform plan` for the given targets
        - if plan is successful and user confirms prompt,
          then the infrastructure is applied.

    kwargs:
        targets: a list of Terraform targets
        action: 'apply' or 'destroy'

    Returns:
        bool: True if the terraform command was successful
    """
    targets = kwargs.get('targets', [])
    action = kwargs.get('action', None)
    tf_action_index = 1  # The index to the terraform 'action'

    var_files = {'conf/lambda.json'}
    tf_opts = ['-var-file=../{}'.format(x) for x in var_files]
    tf_targets = ['-target={}'.format(x) for x in targets]
    tf_command = ['terraform', 'plan'] + tf_opts + tf_targets
    if action == 'destroy':
        tf_command.append('-destroy')

    LOGGER_CLI.debug('Resolving Terraform modules')
    if not run_command(['terraform', 'get'], quiet=True):
        return False

    LOGGER_CLI.info('Planning infrastructure')
    if not run_command(tf_command):
        return False

    if not continue_prompt():
        sys.exit(0)

    if action == 'destroy':
        LOGGER_CLI.info('Destroying infrastructure')
        tf_command[tf_action_index] = action
        tf_command.remove('-destroy')
        tf_command.append('-force')

    elif action:
        tf_command[tf_action_index] = action

    else:
        LOGGER_CLI.info('Creating infrastructure')
        tf_command[tf_action_index] = 'apply'

    if not run_command(tf_command):
        return False

    return True


def status():
    """Display current AWS infrastructure built by Terraform"""
    for cluster, region in CONFIG['clusters'].iteritems():
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

    print '\nUser Access Keys:'
    run_command(['terraform', 'output'])


def rollback(options):
    """Rollback the current production AWS Lambda version by 1

    Notes:
        Ignores if the production version is $LATEST
        Only rollsback if published version is greater than 1
    """
    clusters = CONFIG.clusters()

    if 'all' in options.processor:
        lambda_functions = {'rule_processor', 'alert_processor', 'athena_partition_refresh'}
    else:
        lambda_functions = {'{}_processor'.format(proc) for proc in options.processor
                            if proc != 'athena'}
        if 'athena' in options.processor:
            lambda_functions.add('athena_partition_refresh')

    for cluster in clusters:
        for lambda_function in lambda_functions:
            stream_alert_key = CONFIG['clusters'][cluster]['modules']['stream_alert']
            current_vers = stream_alert_key[lambda_function]['current_version']
            if current_vers != '$LATEST':
                current_vers = int(current_vers)
                if current_vers > 1:
                    new_vers = current_vers - 1
                    CONFIG['clusters'][cluster]['modules']['stream_alert'][lambda_function][
                        'current_version'] = new_vers
                    CONFIG.write()

    targets = ['module.stream_alert_{}'.format(x)
               for x in CONFIG.clusters()]

    if not terraform_generate(config=CONFIG):
        return

    tf_runner(targets=targets)


def deploy(options):
    """Deploy new versions of all Lambda functions

    Steps:
    - Build AWS Lambda deployment package
    - Upload to S3
    - Update lambda.json with uploaded package checksum and S3 key
    - Publish new version
    - Update each cluster's Lambda configuration with latest published version
    - Run Terraform Apply
    """
    processor = options.processor
    # Terraform apply only to the module which contains our lambda functions
    targets = []
    packages = []

    def _publish_version(packages):
        """Publish Lambda versions"""
        for package in packages:
            if package.package_name == 'athena_partition_refresh':
                published = LambdaVersion(
                    config=CONFIG, package=package, clustered_deploy=False).publish_function()
            else:
                published = LambdaVersion(config=CONFIG, package=package).publish_function()
            if not published:
                return False

        return True

    def _deploy_rule_processor():
        """Create Rule Processor package and publish versions"""
        rule_package = RuleProcessorPackage(
            config=CONFIG,
            version=current_version
        )
        rule_package.create_and_upload()
        return rule_package

    def _deploy_alert_processor():
        """Create Alert Processor package and publish versions"""
        alert_package = AlertProcessorPackage(
            config=CONFIG,
            version=current_version
        )
        alert_package.create_and_upload()
        return alert_package

    def _deploy_athena_partition_refresh():
        """Create Athena Partition Refresh package and publish"""
        athena_package = AthenaPackage(
            config=CONFIG,
            version=current_version
        )
        athena_package.create_and_upload()
        return athena_package

    if 'all' in processor:
        targets.extend(['module.stream_alert_{}'.format(x)
                        for x in CONFIG.clusters()])

        packages.append(_deploy_rule_processor())
        packages.append(_deploy_alert_processor())

        # Only include the Athena function if it exists and is enabled
        athena_config = CONFIG['lambda'].get('athena_partition_refresh_config')
        if athena_config and athena_config.get('enabled', False):
            targets.append('module.stream_alert_athena')
            packages.append(_deploy_athena_partition_refresh())

    else:

        if 'rule' in processor:
            targets.extend(['module.stream_alert_{}'.format(x)
                            for x in CONFIG.clusters()])

            packages.append(_deploy_rule_processor())

        if 'alert' in processor:
            targets.extend(['module.stream_alert_{}'.format(x)
                            for x in CONFIG.clusters()])

            packages.append(_deploy_alert_processor())

        if 'athena' in processor:
            targets.append('module.stream_alert_athena')

            packages.append(_deploy_athena_partition_refresh())

    # Regenerate the Terraform configuration with the new S3 keys
    if not terraform_generate(config=CONFIG):
        return

    # Run Terraform: Update the Lambda source code in $LATEST
    if not tf_runner(targets=targets):
        sys.exit(1)

    # TODO(jack) write integration test to verify newly updated function

    # Publish a new production Lambda version
    if not _publish_version(packages):
        return

    # Regenerate the Terraform configuration with the new Lambda versions
    if not terraform_generate(config=CONFIG):
        return

    # Apply the changes to the Lambda aliases
    tf_runner(targets=targets)


def user_input(requested_info, mask, input_restrictions):
    """Prompt user for requested information

    Args:
        requested_info (str): Description of the information needed
        mask (bool): Decides whether to mask input or not

    Returns:
        str: response provided by the user
    """
    response = ''
    prompt = '\nPlease supply {}: '.format(requested_info)

    if not mask:
        while not response:
            response = raw_input(prompt)

        # Restrict having spaces or colons in items (applies to things like
        # descriptors, etc)
        if any(x in input_restrictions for x in response):
            LOGGER_CLI.error(
                'the supplied input should not contain any of the following: %s',
                '"{}"'.format(
                    '", "'.join(input_restrictions)))
            return user_input(requested_info, mask, input_restrictions)
    else:
        while not response:
            response = getpass(prompt=prompt)

    return response


def configure_output(options):
    """Configure a new output for this service

    Args:
        options (argparser): Basically a namedtuple with the service setting
    """
    account_config = CONFIG['global']['account']
    region = account_config['region']
    prefix = account_config['prefix']
    kms_key_alias = account_config['kms_key_alias']
    # Verify that the word alias is not in the config.
    # It is interpolated when the API call is made.
    if 'alias/' in kms_key_alias:
        kms_key_alias = kms_key_alias.split('/')[1]

    # Retrieve the proper service class to handle dispatching the alerts of this services
    output = get_output_dispatcher(options.service,
                                   region,
                                   prefix,
                                   config_outputs.load_outputs_config())

    # If an output for this service has not been defined, the error is logged
    # prior to this
    if not output:
        return

    # get dictionary of OutputProperty items to be used for user prompting
    props = output.get_user_defined_properties()

    for name, prop in props.iteritems():
        # pylint: disable=protected-access
        props[name] = prop._replace(value=user_input(prop.description,
                                                     prop.mask_input,
                                                     prop.input_restrictions))

    service = output.__service__
    config = config_outputs.load_config(props, service)
    # An empty config here means this configuration already exists,
    # so we can ask for user input again for a unique configuration
    if config is False:
        return configure_output(options)

    secrets_bucket = '{}.streamalert.secrets'.format(prefix)
    secrets_key = output.output_cred_name(props['descriptor'].value)

    # Encrypt the creds and push them to S3
    # then update the local output configuration with properties
    if config_outputs.encrypt_and_push_creds_to_s3(region,
                                                   secrets_bucket,
                                                   secrets_key,
                                                   props,
                                                   kms_key_alias):
        updated_config = output.format_output_config(config, props)
        config_outputs.update_outputs_config(config, updated_config, service)

        LOGGER_CLI.info(
            'Successfully saved \'%s\' output configuration for service \'%s\'',
            props['descriptor'].value,
            options.service)
    else:
        LOGGER_CLI.error('An error occurred while saving \'%s\' '
                         'output configuration for service \'%s\'',
                         props['descriptor'].value,
                         options.service)


def _toggle_metrics(options):
    """Enable or disable logging CloudWatch metrics

    Args:
        options (argparser): Contains boolean necessary for toggling metrics
    """
    CONFIG.toggle_metrics(options.enable_metrics, options.clusters, options.functions)


def _create_alarm(options):
    """Create a new CloudWatch alarm for the given metric

    Args:
        options (argparser): Contains all of the necessary info for configuring
            a CloudWatch alarm
    """
    # Perform safety check for max total evaluation period. This logic cannot
    # be performed by argparse so must be performed now.
    seconds_in_day = 86400
    if options.period * options.evaluation_periods > seconds_in_day:
        LOGGER_CLI.error('The product of the value for period multiplied by the '
                         'value for evaluation periods cannot exceed 86,400. 86,400 '
                         'is the number of seconds in one day and an alarm\'s total '
                         'current evaluation period can be no longer than one day.')
        return

    # Check to see if the user is specifying clusters when trying to create an
    # alarm on an aggregate metric. Aggregate metrics encompass all clusters so
    # specification of clusters doesn't have any real effect
    if options.metric_target == 'aggregate' and options.clusters:
        LOGGER_CLI.error('Specifying clusters when creating an alarm on an aggregate '
                         'metric has no effect. Please remove the -c/--clusters flag.')
        return

    CONFIG.add_metric_alarm(vars(options))

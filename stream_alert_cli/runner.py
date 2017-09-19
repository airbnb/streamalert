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

from stream_alert.alert_processor.outputs import get_output_dispatcher
from stream_alert.athena_partition_refresh.main import StreamAlertAthenaClient
from stream_alert_cli import helpers
from stream_alert_cli.config import CLIConfig
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.manage_lambda.handler import lambda_handler
from stream_alert_cli.terraform.handler import terraform_handler
from stream_alert_cli.test import stream_alert_test
import stream_alert_cli.outputs as config_outputs


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


def configure_handler(options):
    """Configure StreamAlert main settings

    Args:
        options (namedtuple): ArgParse command result
    """
    if options.config_key == 'prefix':
        CONFIG.set_prefix(options.config_value)

    elif options.config_key == 'aws_account_id':
        CONFIG.set_aws_account_id(options.config_value)


def run_command(args=None, **kwargs):
    """Alias to CLI Helpers.run_command"""
    return helpers.run_command(args, **kwargs)


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

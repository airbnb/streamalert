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
from app_integrations.apps.app_base import get_app
from stream_alert.rule_processor.handler import StreamAlert
from stream_alert.alert_processor.outputs import get_output_dispatcher
from stream_alert.athena_partition_refresh.main import StreamAlertAthenaClient
from stream_alert_cli.apps import save_app_auth_info
from stream_alert_cli.config import CLIConfig
from stream_alert_cli.helpers import user_input
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.manage_lambda.handler import lambda_handler
import stream_alert_cli.outputs as config_outputs
from stream_alert_cli.terraform._common import enabled_firehose_logs
from stream_alert_cli.terraform.handler import terraform_handler
from stream_alert_cli.test import stream_alert_test


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
        lambda_handler(options, CONFIG)

    elif options.command == 'live-test':
        stream_alert_test(options, CONFIG)

    elif options.command == 'validate-schemas':
        stream_alert_test(options, CONFIG)

    elif options.command == 'terraform':
        terraform_handler(options, CONFIG)

    elif options.command == 'configure':
        configure_handler(options)

    elif options.command == 'athena':
        athena_handler(options)

    elif options.command == 'metrics':
        _toggle_metrics(options)

    elif options.command == 'create-alarm':
        _create_alarm(options)

    elif options.command == 'app':
        _app_integration_handler(options)


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
        if not options.bucket:
            LOGGER_CLI.error('Missing command line argument --bucket')
            return

        if not options.refresh_type:
            LOGGER_CLI.error('Missing command line argument --refresh_type')
            return

        if options.type == 'data':
            if not options.table_name:
                LOGGER_CLI.error('Missing command line argument --table_name')
                return

            if options.table_name not in enabled_firehose_logs(CONFIG):
                LOGGER_CLI.error('Table name %s missing from configuration or '
                                 'is not enabled.',
                                 options.table_name)
                return

            if athena_client.check_table_exists(options.table_name):
                LOGGER_CLI.info('The \'%s\' table already exists.',
                                options.table_name)
                return

            log_info = CONFIG['logs'][options.table_name.replace('_', ':', 1)]
            schema = dict(log_info['schema'])
            schema_statement = ''

            sanitized_schema = StreamAlert.sanitize_keys(schema)

            athena_schema = {}
            schema_type_mapping = {
                'string': 'string',
                'integer': 'int',
                'boolean': 'boolean',
                'float': 'decimal',
                dict: 'map<string, string>',
                list: 'array<string>'
            }

            def add_to_athena_schema(schema, root_key=''):
                """Helper function to add sanitized schemas to the Athena table schema"""
                # Setup the root_key dict
                if root_key and not athena_schema.get(root_key):
                    athena_schema[root_key] = {}

                for key_name, key_type in schema.iteritems():
                    # When using special characters in the beginning or end
                    # of a column name, they have to be wrapped in backticks
                    key_name = '`{}`'.format(key_name)

                    special_key = None
                    # Transform the {} or [] into hashable types
                    if key_type == {}:
                        special_key = dict
                    elif key_type == []:
                        special_key = list
                    # Cast nested dict as a string for now
                    # TODO(jacknagz): support recursive schemas
                    elif isinstance(key_type, dict):
                        special_key = 'string'

                    # Account for envelope keys
                    if root_key:
                        if special_key is not None:
                            athena_schema[root_key][key_name] = schema_type_mapping[special_key]
                        else:
                            athena_schema[root_key][key_name] = schema_type_mapping[key_type]
                    else:
                        if special_key is not None:
                            athena_schema[key_name] = schema_type_mapping[special_key]
                        else:
                            athena_schema[key_name] = schema_type_mapping[key_type]

            add_to_athena_schema(sanitized_schema)

            # Support envelope keys
            configuration_options = log_info.get('configuration')
            if configuration_options:
                envelope_keys = configuration_options.get('envelope_keys')
                if envelope_keys:
                    sanitized_envelope_keys = StreamAlert.sanitize_keys(envelope_keys)
                    # Note: this key is wrapped in backticks to be Hive compliant
                    add_to_athena_schema(sanitized_envelope_keys, '`streamalert:envelope_keys`')

            for key_name, key_type in athena_schema.iteritems():
                # Account for nested structs
                if isinstance(key_type, dict):
                    struct_schema = ''.join(['{0}:{1},'.format(sub_key, sub_type)
                                             for sub_key, sub_type
                                             in key_type.iteritems()])
                    nested_schema_statement = '{0} struct<{1}>, '.format(
                        key_name,
                        # Use the minus index to remove the last comma
                        struct_schema[:-1])
                    schema_statement += nested_schema_statement
                else:
                    schema_statement += '{0} {1},'.format(key_name, key_type)

            query = ('CREATE EXTERNAL TABLE {table_name} ({schema}) '
                     'PARTITIONED BY (dt string) '
                     'ROW FORMAT SERDE \'org.openx.data.jsonserde.JsonSerDe\' '
                     'LOCATION \'s3://{bucket}/{table_name}/\''.format(
                         table_name=options.table_name,
                         # Use the minus index to remove the last comma
                         schema=schema_statement[:-1],
                         bucket=options.bucket))

        elif options.type == 'alerts':
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

        if query:
            create_table_success, _ = athena_client.run_athena_query(
                query=query,
                database='streamalert')

            if create_table_success:
                CONFIG['lambda']['athena_partition_refresh_config'] \
                      ['refresh_type'][options.refresh_type][options.bucket] = options.type
                CONFIG.write()
                table_name = options.type if options.type == 'alerts' else options.table_name
                LOGGER_CLI.info('The %s table was successfully created!', table_name)


def configure_handler(options):
    """Configure StreamAlert main settings

    Args:
        options (namedtuple): ArgParse command result
    """
    if options.config_key == 'prefix':
        CONFIG.set_prefix(options.config_value)

    elif options.config_key == 'aws_account_id':
        CONFIG.set_aws_account_id(options.config_value)


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


def _app_integration_handler(options):
    """Perform app integration related functions

    Args:
        options (argparser): Contains all of the necessary info for configuring
            a new app integration or updating an existing one
    """
    if not options:
        return

    # Convert the options to a dict
    app_info = vars(options)

    # Add the region and prefix for this StreamAlert instance to the app info
    app_info['region'] = str(CONFIG['global']['account']['region'])
    app_info['prefix'] = str(CONFIG['global']['account']['prefix'])

    # Function name follows the format: '<prefix>_<cluster>_<service>_<app_name>_app
    func_parts = ['prefix', 'cluster', 'type', 'app_name']

    # Create a new app integration function
    if options.subcommand == 'new':
        app_info['function_name'] = '_'.join([app_info.get(value)
                                              for value in func_parts] + ['app'])

        CONFIG.add_app_integration(app_info)
        return

    # Update the auth information for an existing app integration function
    if options.subcommand == 'update-auth':
        cluster_config = CONFIG['clusters'][app_info['cluster']]
        if not app_info['app_name'] in cluster_config['modules'].get('stream_alert_apps', {}):
            LOGGER_CLI.error('App integration with name \'%s\' does not exist for cluster \'%s\'',
                             app_info['app_name'], app_info['cluster'])
            return

        # Get the type for this app integration from the current
        # config so we can update it properly
        app_info['type'] = cluster_config['modules']['stream_alert_apps'] \
                                         [app_info['app_name']]['type']

        app_info['function_name'] = '_'.join([app_info.get(value)
                                              for value in func_parts] + ['app'])

        app = get_app(app_info)

        if not save_app_auth_info(app, app_info, True):
            return

        return

    # List all of the available app integrations, broken down by cluster
    if options.subcommand == 'list':
        all_info = {cluster: cluster_config['modules'].get('stream_alert_apps')
                    for cluster, cluster_config in CONFIG['clusters'].iteritems()}

        for cluster, info in all_info.iteritems():
            print '\nCluster: {}\n'.format(cluster)
            if not info:
                print '\tNo Apps configured\n'
                continue

            for name, details in info.iteritems():
                print '\tName: {}'.format(name)
                print '\n'.join(['\t\t{key}:{padding_char:<{padding_count}}{value}'.format(
                    key=key_name,
                    padding_char=' ',
                    padding_count=30 - (len(key_name)),
                    value=value
                ) for key_name, value in details.iteritems()] + ['\n'])

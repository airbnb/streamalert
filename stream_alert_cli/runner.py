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
from app_integrations.apps.app_base import StreamAlertApp
from stream_alert.alert_processor.outputs.output_base import StreamAlertOutput
from stream_alert_cli.apps import save_app_auth_info
from stream_alert_cli.athena.handler import athena_handler
from stream_alert_cli.config import CLIConfig
from stream_alert_cli.helpers import user_input
from stream_alert_cli.kinesis.handler import kinesis_handler
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.manage_lambda.handler import lambda_handler
from stream_alert_cli.terraform.handler import terraform_handler
from stream_alert_cli.test import stream_alert_test
from stream_alert_cli.threat_intel_downloader.handler import (
    handler as threat_intel_downloader_handler
)
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
    cli_load_message = 'Issues? Report here: https://github.com/airbnb/streamalert/issues'
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
        athena_handler(options, CONFIG)

    elif options.command == 'metrics':
        _toggle_metrics(options)

    elif options.command == 'create-alarm':
        _create_alarm(options)

    elif options.command == 'app':
        _app_integration_handler(options)

    elif options.command == 'kinesis':
        kinesis_handler(options, CONFIG)

    elif options.command == 'threat_intel':
        _threat_intel_handler(options, CONFIG)

    elif options.command == 'threat_intel_downloader':
        threat_intel_downloader_handler(options, CONFIG)


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
    output = StreamAlertOutput.get_dispatcher(options.service)

    # If an output for this service has not been defined, the error is logged
    # prior to this
    if not output:
        return

    # get dictionary of OutputProperty items to be used for user prompting
    props = output.get_user_defined_properties()

    for name, prop in props.iteritems():
        # pylint: disable=protected-access
        props[name] = prop._replace(
            value=user_input(prop.description, prop.mask_input, prop.input_restrictions))

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
    if config_outputs.encrypt_and_push_creds_to_s3(region, secrets_bucket, secrets_key, props,
                                                   kms_key_alias):
        updated_config = output.format_output_config(config, props)
        config_outputs.update_outputs_config(config, updated_config, service)

        LOGGER_CLI.info('Successfully saved \'%s\' output configuration for service \'%s\'',
                        props['descriptor'].value, options.service)
    else:
        LOGGER_CLI.error('An error occurred while saving \'%s\' '
                         'output configuration for service \'%s\'', props['descriptor'].value,
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

        app = StreamAlertApp.get_app(app_info, False)

        if not save_app_auth_info(app, app_info, True):
            return

        return

    # List all of the available app integrations, broken down by cluster
    if options.subcommand == 'list':
        all_info = {
            cluster: cluster_config['modules'].get('stream_alert_apps')
            for cluster, cluster_config in CONFIG['clusters'].iteritems()
        }

        for cluster, info in all_info.iteritems():
            print '\nCluster: {}\n'.format(cluster)
            if not info:
                print '\tNo Apps configured\n'
                continue

            for name, details in info.iteritems():
                print '\tName: {}'.format(name)
                print '\n'.join([
                    '\t\t{key}:{padding_char:<{padding_count}}{value}'.format(
                        key=key_name,
                        padding_char=' ',
                        padding_count=30 - (len(key_name)),
                        value=value) for key_name, value in details.iteritems()
                ] + ['\n'])

def _threat_intel_handler(options, config):
    """Configure Threat Intel from command line

    Args:
        options (namedtuple): The parsed args passed from the CLI
        config (CLIConfig): Loaded StreamAlert CLI
    """
    if not options:
        return

    if options.subcommand == 'enable':
        config.add_threat_intel(vars(options))

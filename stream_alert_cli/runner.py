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
from stream_alert_cli.apps.handler import app_handler
from stream_alert_cli.athena.handler import athena_handler
from stream_alert_cli.config import CLIConfig
from stream_alert_cli.kinesis.handler import kinesis_handler
from stream_alert_cli.logger import LOGGER_CLI, set_logger_levels
from stream_alert_cli.manage_lambda.deploy import deploy_handler
from stream_alert_cli.manage_lambda.rollback import rollback_handler
from stream_alert_cli.outputs.handler import output_handler
from stream_alert_cli.rule_table import rule_staging_handler
from stream_alert_cli.terraform.generate import terraform_generate_handler
from stream_alert_cli.terraform.handlers import (
    terraform_build_handler,
    terraform_clean_handler,
    terraform_destroy_handler,
    terraform_init,
)
from stream_alert_cli.test.handler import test_handler
from stream_alert_cli.threat_intel_downloader.handler import threat_intel_downloader_handler


def cli_runner(args):
    """Main StreamAlert CLI handler

    Args:
        options (argparse.Namespace): command line arguments passed from the argparser.
            Contains the following keys for terraform commands:
                (command, subcommand, target)
            Contains the following keys for lambda commands:
                (command, subcommand, env, func, source)
    """
    config = CLIConfig()

    cli_load_message = 'Issues? Report here: https://github.com/airbnb/streamalert/issues'
    LOGGER_CLI.info(cli_load_message)

    if args.debug:
        set_logger_levels('DEBUG')

    cmds = {
        'app': lambda opts: app_handler(opts, config),
        'athena': lambda opts: athena_handler(opts, config),
        'build': lambda opts: terraform_build_handler(opts, config),
        'clean': lambda opts: terraform_clean_handler(config),
        'configure': lambda opts: configure_handler(opts, config),
        'create-alarm': lambda opts: _create_alarm_handler(opts, config),
        'create-cluster-alarm': lambda opts: _create_alarm_handler(opts, config),
        'custom-metrics': lambda opts: _custom_metrics_handler(opts, config),
        'deploy': lambda opts: deploy_handler(opts, config),
        'destroy': lambda opts: terraform_destroy_handler(opts, config),
        'generate': lambda opts: terraform_generate_handler(config),
        'init': lambda opts: terraform_init(opts, config),
        'kinesis': lambda opts: kinesis_handler(opts, config),
        'output': lambda opts: output_handler(opts, config),
        'rollback': lambda opts: rollback_handler(opts, config),
        'rule-staging': lambda opts: rule_staging_handler(opts, config),
        'status': lambda opts: _status_handler(config),
        'test': lambda opts: test_handler(opts, config),
        'threat-intel': lambda opts: _threat_intel_handler(opts, config),
        'threat-intel-downloader': lambda opts: threat_intel_downloader_handler(opts, config),
    }

    cmds[args.command](args)
    LOGGER_CLI.info('Completed')


def configure_handler(options, config):
    """Configure StreamAlert main settings

    Args:
        options (namedtuple): ArgParse command result
    """
    if options.config_key == 'prefix':
        config.set_prefix(options.config_value)

    elif options.config_key == 'aws_account_id':
        config.set_aws_account_id(options.config_value)


def _custom_metrics_handler(options, config):
    """Enable or disable logging CloudWatch metrics

    Args:
        options (argparse.Namespace): Contains boolean necessary for toggling metrics
    """
    config.toggle_metrics(
        *options.functions,
        enabled=options.enable_custom_metrics,
        clusters=options.clusters
    )

def _status_handler(config):
    """Display current AWS infrastructure built by Terraform

    Args:
        config (CLIConfig): Loaded StreamAlert CLI
    """
    # TODO: this is severely broken/outdated. fix up
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


def _create_alarm_handler(options, config):
    """Create a new CloudWatch alarm for the given metric

    Args:
        options (argparse.Namespace): Contains all of the necessary info for configuring
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

    config.add_metric_alarm(vars(options))


def _threat_intel_handler(options, config):
    """Configure Threat Intel from command line

    Args:
        options (namedtuple): The parsed args passed from the CLI
        config (CLIConfig): Loaded StreamAlert CLI
    """
    config.add_threat_intel(vars(options))

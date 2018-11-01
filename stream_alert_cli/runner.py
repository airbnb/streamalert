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
from __future__ import print_function
from stream_alert.shared import CLUSTERED_FUNCTIONS
from stream_alert.shared.logger import get_logger
from stream_alert_cli.apps.handler import app_handler
from stream_alert_cli.athena.handler import athena_handler
from stream_alert_cli.config import CLIConfig
from stream_alert_cli.kinesis.handler import kinesis_handler
from stream_alert_cli.logger import set_logger_levels
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

LOGGER = get_logger(__name__)


def cli_runner(args):
    """Main StreamAlert CLI handler

    Args:
        options (argparse.Namespace): command line arguments passed from the argparser.
            Contains the following keys for terraform commands:
                (command, subcommand, target)
            Contains the following keys for lambda commands:
                (command, subcommand, env, func, source)
    Returns:
        bool: False if errors occurred, True otherwise
    """
    config = CLIConfig()

    set_logger_levels(args.debug)

    LOGGER.info('Issues? Report here: https://github.com/airbnb/streamalert/issues')

    cmds = {
        'app': lambda opts: app_handler(opts, config),
        'athena': lambda opts: athena_handler(opts, config),
        'build': lambda opts: terraform_build_handler(opts, config),
        'clean': lambda opts: terraform_clean_handler(),
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

    result = cmds[args.command](args)
    LOGGER.info('Completed')
    return result


def configure_handler(options, config):
    """Configure StreamAlert main settings

    Args:
        options (argparse.Namespace): ArgParse command result

    Returns:
        bool: False if errors occurred, True otherwise
    """
    if options.key == 'prefix':
        return config.set_prefix(options.value)

    elif options.key == 'aws_account_id':
        return config.set_aws_account_id(options.value)


def _custom_metrics_handler(options, config):
    """Enable or disable logging CloudWatch metrics

    Args:
        options (argparse.Namespace): Contains boolean necessary for toggling metrics

    Returns:
        bool: False if errors occurred, True otherwise
    """
    config.toggle_metrics(
        *options.functions,
        enabled=options.enable_custom_metrics,
        clusters=options.clusters
    )

    return True


def _status_handler(config):
    """Display current AWS infrastructure built by Terraform

    Args:
        config (CLIConfig): Loaded StreamAlert config

    Returns:
        bool: False if errors occurred, True otherwise
    """
    def _format_key(key):
        return key.replace('_', ' ').title()

    def _format_header(value, section_header=False):
        char = '=' if section_header else '+'
        value = value if section_header else _format_key(value)
        return '\n{value:{char}^60}'.format(char=char, value='  {}  '.format(value))

    def _print_row(key, value):
        key = _format_key(key)
        print('{}: {}'.format(key, value))

    print(_format_header('Global Account Settings', True))
    for key in sorted(['aws_account_id', 'prefix', 'region']):
        value = config['global']['account'][key]
        _print_row(key, value)

    lambda_keys = sorted([
        'concurrency_limit',
        'enable_custom_metrics',
        'log_level',
        'log_retention_days',
        'memory',
        'timeout',
        'schedule_expression'
    ])
    for name in set((config['lambda'])):
        config_value = config['lambda'][name]
        name = name.replace('_config', '')
        if name in CLUSTERED_FUNCTIONS:
            continue

        print(_format_header(name))
        for key in lambda_keys:
            _print_row(key, config_value.get(key))

    cluster_non_func_keys = sorted(['enable_threat_intel'])
    for cluster in sorted(config['clusters']):
        sa_config = config['clusters'][cluster]['modules']['stream_alert']

        print(_format_header('Cluster: {}'.format(cluster), True))
        for key in cluster_non_func_keys:
            _print_row(key, sa_config.get(key))

        for function in CLUSTERED_FUNCTIONS:
            config_value = sa_config['{}_config'.format(function)]

            print(_format_header(function))
            for key in lambda_keys:
                _print_row(key, config_value.get(key))

    return True


def _create_alarm_handler(options, config):
    """Create a new CloudWatch alarm for the given metric

    Args:
        options (argparse.Namespace): Contains all of the necessary info for configuring
            a CloudWatch alarm

    Returns:
        bool: False if errors occurred, True otherwise
    """
    # Perform safety check for max total evaluation period. This logic cannot
    # be performed by argparse so must be performed now.
    seconds_in_day = 86400
    if options.period * options.evaluation_periods > seconds_in_day:
        LOGGER.error('The product of the value for period multiplied by the '
                     'value for evaluation periods cannot exceed 86,400. 86,400 '
                     'is the number of seconds in one day and an alarm\'s total '
                     'current evaluation period can be no longer than one day.')
        return False

    return config.add_metric_alarm(vars(options))


def _threat_intel_handler(options, config):
    """Configure Threat Intel from command line

    Args:
        options (argparse.Namespace): The parsed args passed from the CLI
        config (CLIConfig): Loaded StreamAlert config

    Returns:
        bool: False if errors occurred, True otherwise
    """
    config.add_threat_intel(vars(options))
    return True

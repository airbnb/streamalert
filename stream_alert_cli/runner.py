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
from stream_alert.shared.logger import get_logger
from stream_alert_cli.apps.handler import AppCommand
from stream_alert_cli.athena.handler import AthenaCommand
from stream_alert_cli.config import CLIConfig
from stream_alert_cli.configure.handler import ConfigureCommand
from stream_alert_cli.kinesis.handler import KinesisCommand
from stream_alert_cli.logger import set_logger_levels
from stream_alert_cli.lookup_tables.handler import LookupTablesCommand
from stream_alert_cli.manage_lambda.deploy import DeployCommand
from stream_alert_cli.manage_lambda.rollback import RollbackCommand
from stream_alert_cli.metrics_alarms.handler import MetricAlarmCommand, CustomMetricsCommand
from stream_alert_cli.outputs.handler import OutputCommand
from stream_alert_cli.rule_table import RuleStagingCommand
from stream_alert_cli.status.handler import StatusCommand
from stream_alert_cli.terraform.handlers import (
    TerraformBuildCommand,
    TerraformCleanCommand,
    TerraformDestroyCommand,
    TerraformInitCommand,
    TerraformListTargetsCommand,
    TerraformGenerateCommand)
from stream_alert_cli.test.handler import TestCommand
from stream_alert_cli.threat_intel_downloader.handler import ThreatIntelDownloaderCommand, ThreatIntelCommand

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
        'app': lambda opts: AppCommand.handler(opts, config),
        'athena': lambda opts: AthenaCommand.handler(opts, config),
        'build': lambda opts: TerraformBuildCommand.handler(opts, config),
        'clean': lambda opts: TerraformCleanCommand.handler(opts, config),
        'configure': lambda opts: ConfigureCommand.handler(opts, config),
        'create-alarm': lambda opts: MetricAlarmCommand.handler(opts, config),
        'create-cluster-alarm': lambda opts: MetricAlarmCommand.handler(opts, config),
        'custom-metrics': lambda opts: CustomMetricsCommand.handler(opts, config),
        'deploy': lambda opts: DeployCommand.handler(opts, config),
        'destroy': lambda opts: TerraformDestroyCommand.handler(opts, config),
        'generate': lambda opts: TerraformGenerateCommand.handler(opts, config),
        'init': lambda opts: TerraformInitCommand.handler(opts, config),
        'kinesis': lambda opts: KinesisCommand.handler(opts, config),
        'list-targets': lambda opts: TerraformListTargetsCommand.handler(opts, config),
        'lookup-tables': lambda opts: LookupTablesCommand.handler(opts, config),
        'output': lambda opts: OutputCommand.handler(opts, config),
        'rollback': lambda opts: RollbackCommand.handler(opts, config),
        'rule-staging': lambda opts: RuleStagingCommand.handler(opts, config),
        'status': lambda opts: StatusCommand.handler(opts, config),
        'test': lambda opts: TestCommand.handler(opts, config),
        'threat-intel': lambda opts: ThreatIntelCommand.handler(opts, config),
        'threat-intel-downloader': lambda opts: ThreatIntelDownloaderCommand.handler(opts, config),
    }

    result = cmds[args.command](args)
    LOGGER.info('Completed')
    return result


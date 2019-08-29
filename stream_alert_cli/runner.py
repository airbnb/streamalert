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
from stream_alert_cli.threat_intel_downloader.handler import (
    ThreatIntelCommand,
    ThreatIntelDownloaderCommand,
)
from stream_alert_cli.utils import CliCommand

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

    cmds = StreamAlertCliCommandRepository.command_handlers(config)

    result = cmds[args.command](args)
    LOGGER.info('Completed')
    return result


class StreamAlertCliCommandRepository(object):
    COMMANDS = {}

    @classmethod
    def register(cls, command, cli_command):
        if not issubclass(cli_command, CliCommand):
            LOGGER.error('Invalid CLI Command in registry')
            return False

        cls.COMMANDS[command] = cli_command

    @classmethod
    def register_all(cls):
        cmds = {
            'app': AppCommand,
            'athena': AthenaCommand,
            'build': TerraformBuildCommand,
            'clean': TerraformCleanCommand,
            'configure': ConfigureCommand,
            'create-alarm': MetricAlarmCommand,
            'create-cluster-alarm': MetricAlarmCommand,
            'custom-metrics': CustomMetricsCommand,
            'deploy': DeployCommand,
            'destroy': TerraformDestroyCommand,
            'generate': TerraformGenerateCommand,
            'init': TerraformInitCommand,
            'kinesis': KinesisCommand,
            'list-targets': TerraformListTargetsCommand,
            'lookup-tables': LookupTablesCommand,
            'output': OutputCommand,
            'rollback': RollbackCommand,
            'rule-staging': RuleStagingCommand,
            'status': StatusCommand,
            'test': TestCommand,
            'threat-intel': ThreatIntelCommand,
            'threat-intel-downloader': ThreatIntelDownloaderCommand,
        }

        for command, cli_command in cmds.iteritems():
            cls.register(command, cli_command)

    @classmethod
    def command_handlers(cls, config):
        return {
            command: lambda opts: cli_command.handler(opts, config)
            for command, cli_command in cls.COMMANDS.iteritems()
        }

    @classmethod
    def command_parsers(cls):
        return {
            command: (cli_command.setup_subparser, cli_command.description)
            for command, cli_command in cls.COMMANDS.iteritems()
        }

StreamAlertCliCommandRepository.register_all()

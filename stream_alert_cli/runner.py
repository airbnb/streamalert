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
from stream_alert_cli.metrics_alarms.handler import (
    CreateMetricAlarmCommand,
    CreateClusterMetricAlarmCommand,
    CustomMetricsCommand,
)
from stream_alert_cli.outputs.handler import OutputCommand
from stream_alert_cli.rule_table import RuleStagingCommand
from stream_alert_cli.status.handler import StatusCommand
from stream_alert_cli.terraform.generate import TerraformGenerateCommand
from stream_alert_cli.terraform.handlers import (
    TerraformBuildCommand,
    TerraformCleanCommand,
    TerraformDestroyCommand,
    TerraformInitCommand,
    TerraformListTargetsCommand,
)
from stream_alert_cli.test.handler import TestCommand
from stream_alert_cli.threat_intel.handler import ThreatIntelCommand
from stream_alert_cli.threat_intel_downloader.handler import ThreatIntelDownloaderCommand
from stream_alert_cli.utils import CLICommand

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

    cmds = StreamAlertCLICommandRepository.command_handlers(config)

    result = cmds[args.command](args)
    LOGGER.info('Completed')
    return result


class StreamAlertCLICommandRepository:
    """
    This repository class contains and manages all StreamAlert manage.py commands that are
    configured on this repository.
    """
    COMMANDS = {}

    @classmethod
    def register(cls, command, cli_command):
        if not issubclass(cli_command, CLICommand):
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
            'create-alarm': CreateMetricAlarmCommand,
            'create-cluster-alarm': CreateClusterMetricAlarmCommand,
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

        for command, cli_command in cmds.items():
            cls.register(command, cli_command)

    @classmethod
    def command_handlers(cls, config):
        """
        Returns a dict of command strings mapped to their respective CLICommand classes.
        """
        return {
            command: lambda opts, cmd=cli_command: cmd.handler(opts, config)
            for command, cli_command in cls.COMMANDS.items()
        }

    @classmethod
    def command_parsers(cls):
        """
        Returns a dict of commands mapped to tuples. The first element of the tuple is the
        CLICommand.setup_subparser function for that command. The second element is a string
        description of that CLICommand.
        """
        return {
            command: (cli_command.setup_subparser, cli_command.description)
            for command, cli_command in cls.COMMANDS.items()
        }


StreamAlertCLICommandRepository.register_all()

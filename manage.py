#! /usr/bin/env python
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

---------------------------------------------------------------------------

This script builds StreamAlert AWS infrastructure, is responsible for
deploying to AWS Lambda, and publishing production versions.

To run terraform by hand, change to the terraform directory and run:

terraform <cmd>
"""
# pylint: disable=too-many-lines
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import sys

from stream_alert import __version__ as version
from stream_alert_cli.apps.handler import AppCommand
from stream_alert_cli.athena.handler import AthenaCommand
from stream_alert_cli.configure.handler import ConfigureCommand
from stream_alert_cli.kinesis.handler import KinesisCommand
from stream_alert_cli.lookup_tables.handler import LookupTablesCommand
from stream_alert_cli.manage_lambda.deploy import DeployCommand
from stream_alert_cli.manage_lambda.rollback import RollbackCommand
from stream_alert_cli.metrics_alarms.handler import CustomMetricsCommand, MetricAlarmCommand
from stream_alert_cli.outputs.handler import OutputCommand
from stream_alert_cli.rule_table import RuleStagingCommand
from stream_alert_cli.status.handler import StatusCommand
from stream_alert_cli.terraform.handlers import (
    TerraformBuildCommand,
    TerraformCleanCommand,
    TerraformDestroyCommand,
    TerraformGenerateCommand,
    TerraformInitCommand,
    TerraformListTargetsCommand
)
from stream_alert_cli.runner import cli_runner
from stream_alert_cli.test.handler import TestCommand
from stream_alert_cli.threat_intel_downloader.handler import (
    ThreatIntelCommand,
    ThreatIntelDownloaderCommand,
)
from stream_alert_cli.utils import generate_subparser



def build_parser():
    """Build the argument parser."""

    # Map of top-level commands and their setup functions/description
    # New top-level commands should be added to this dictionary
    commands = {
        'app': (
            AppCommand.setup_subparser,
            'Create, list, or update a StreamAlert app to poll logs from various services'
        ),
        'athena': (
            AthenaCommand.setup_subparser,
            'Perform actions related to Athena'
        ),
        'build': (
            TerraformBuildCommand.setup_subparser,
            'Run terraform against StreamAlert modules, optionally targeting specific modules'
        ),
        'clean': (
            TerraformCleanCommand.setup_subparser,
            'Remove current Terraform files'
        ),
        'configure': (
            ConfigureCommand.setup_subparser,
            'Configure global StreamAlert settings'
        ),
        'create-alarm': (
            MetricAlarmCommand.setup_subparser,
            'Add a global CloudWatch alarm for predefined metrics for a given function'
        ),
        'create-cluster-alarm': (
            MetricAlarmCommand.setup_subparser,
            'Add a CloudWatch alarm for predefined metrics for a given cluster/function'
        ),
        'custom-metrics': (
            CustomMetricsCommand.setup_subparser,
            'Enable or disable custom metrics for the lambda functions'
        ),
        'deploy': (
            DeployCommand.setup_subparser,
            'Deploy the specified AWS Lambda function(s)'
        ),
        'destroy': (
            TerraformDestroyCommand.setup_subparser,
            'Destroy StreamAlert infrastructure, optionally targeting specific modules',
        ),
        'generate': (
            TerraformGenerateCommand.setup_subparser,
            'Generate Terraform files from JSON cluster files'
        ),
        'init': (
            TerraformInitCommand.setup_subparser,
            'Initialize StreamAlert infrastructure'
        ),
        'kinesis': (
            KinesisCommand.setup_subparser,
            'Update AWS Kinesis settings and run Terraform to apply changes'
        ),
        'list-targets': (
            TerraformListTargetsCommand.setup_subparser,
            'List available Terraform modules to be used for targeted builds'
        ),
        'lookup-tables': (
            LookupTablesCommand.setup_subparser,
            'List commands for LookupTables'
        ),
        'output': (
            OutputCommand.setup_subparser,
            'Create a new StreamAlert output'
        ),
        'rollback': (
            RollbackCommand.setup_subparser,
            'Rollback the specified AWS Lambda function(s)'
        ),
        'rule-staging': (
            RuleStagingCommand.setup_subparser,
            'Perform actions related to rule staging'
        ),
        'status': (
            StatusCommand.setup_subparser,
            'Output information on currently configured infrastructure'
        ),
        'test': (
            TestCommand.setup_subparser,
            'Perform various integration/functional tests'
        ),
        'threat-intel': (
            ThreatIntelCommand.setup_subparser,
            'Enable/disable and configure the StreamAlert Threat Intelligence feature'
        ),
        'threat-intel-downloader': (
            ThreatIntelDownloaderCommand.setup_subparser,
            'Configure and update the threat intel downloader'
        )
    }

    description_template = """
StreamAlert v{}

Configure, test, build, and deploy StreamAlert

Available Commands:

{}

For additional help with any command above, try:

        {} [command] --help
"""

    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        prog=__file__
    )

    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version=version
    )

    parser.add_argument(
        '-d',
        '--debug',
        help='enable debugging logger output for all of the StreamAlert loggers',
        action='store_true'
    )

    # Dynamically generate subparsers, and create a 'commands' block for the prog description
    command_block = []
    subparsers = parser.add_subparsers()
    command_col_size = max([len(command) for command in commands]) + 10
    for command in sorted(commands):
        setup_subparser_func, description = commands[command]
        subparser = generate_subparser(subparsers, command, description=description)

        # If there are additional arguments to set for this command, call its setup function
        if setup_subparser_func:
            setup_subparser_func(subparser)

        command_block.append(
            '\t{command: <{pad}}{description}'.format(
                command=command,
                pad=command_col_size,
                description=description
            )
        )

    # Update the description on the top level parser
    parser.description = description_template.format(
        version,
        '\n'.join(command_block),
        __file__
    )

    parser.epilog = 'Issues? Please report here: https://github.com/airbnb/streamalert/issues'

    return parser


def main():
    """Entry point for the CLI."""
    parser = build_parser()
    options = parser.parse_args()

    # Exit with the result, which will be False if an error occurs, or True otherwise
    sys.exit(not cli_runner(options))


if __name__ == "__main__":
    main()

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

terraform <cmd> -var-file=../terraform.tfvars -var-file=../variables.json
"""
from argparse import ArgumentParser, RawTextHelpFormatter, SUPPRESS as ARGPARSE_SUPPRESS
import os

from stream_alert_cli import __version__ as version
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.runner import cli_runner


def _add_output_subparser(subparsers):
    """Add the output subparser: manage.py output [subcommand] [options]"""
    output_usage = 'manage.py output [subcommand] [options]'
    output_description = ("""
StreamAlertCLI v{}
Define new StreamAlert outputs to send alerts to

Available Subcommands:

    manage.py output new [options]    Create a new StreamAlert output

Examples:

    manage.py output new --service <service_name>
    manage.py output new --service aws-s3
    manage.py output new --service pagerduty
    manage.py output new --service slack

""".format(version))
    output_parser = subparsers.add_parser(
        'output',
        description=output_description,
        usage=output_usage,
        formatter_class=RawTextHelpFormatter,
        help='Define a new output to send alerts to'
    )

    # Set the name of this parser to 'output'
    output_parser.set_defaults(command='output')

    # Output parser arguments
    # The CLI library handles all configuration logic
    output_parser.add_argument(
        'subcommand',
        choices=['new'],
        help=ARGPARSE_SUPPRESS
    )
    # Output service options
    output_parser.add_argument(
        '--service',
        choices=['aws-lambda', 'aws-s3', 'pagerduty', 'phantom', 'slack'],
        required=True,
        help=ARGPARSE_SUPPRESS
    )
    output_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )


def _add_live_test_subparser(subparsers):
    """Add the live-test subparser: manage.py live-test [options]"""
    live_test_usage = 'manage.py live-test [options]'
    live_test_description = ("""
StreamAlertCLI v{}
Run end-to-end tests that will attempt to send alerts

Available Options:

    --cluster               The cluster name to use for live testing
    --rules                 Name of rules to test, separated by spaces
    --debug                 Enable Debug logger output

Examples:

    manage.py live-test --cluster prod
    manage.py live-test --rules

""".format(version))
    live_test_parser = subparsers.add_parser(
        'live-test',
        description=live_test_description,
        usage=live_test_usage,
        formatter_class=RawTextHelpFormatter,
        help=ARGPARSE_SUPPRESS
    )

    # set the name of this parser to 'live-test'
    live_test_parser.set_defaults(command='live-test')

    # get cluster choices from available files
    clusters = []
    for _, _, files in os.walk('conf/clusters'):
        clusters.extend(os.path.splitext(cluster)[0] for cluster in files)

    # add clusters for user to pick from
    live_test_parser.add_argument(
        '-c', '--cluster',
        choices=clusters,
        help=ARGPARSE_SUPPRESS,
        required=True
    )

    # add the optional ability to test against a rule/set of rules
    live_test_parser.add_argument(
        '-r', '--rules',
        nargs='+',
        help=ARGPARSE_SUPPRESS
    )

    # allow verbose output for the CLI with te --debug option
    live_test_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )


def _add_lambda_subparser(subparsers):
    """Add the Lambda subparser: manage.py lambda [subcommand] [options]"""
    lambda_usage = 'manage.py lambda [subcommand] [options]'
    lambda_description = ("""
StreamAlertCLI v{}
Deploy, Rollback, and Test StreamAlert Lambda functions

Available Subcommands:

    manage.py lambda deploy [options]         Deploy Lambda functions
    manage.py lambda rollback [options]       Rollback Lambda functions
    manage.py lambda test [options]           Run rule tests

Available Options:

    --processor                                         The name of the Lambda function to manage.
                                                        Valid options include: rule, alert, or all.
    --debug                                             Enable Debug logger output.
    --rules                                             List of rules to test, separated by spaces.

Examples:

    manage.py lambda deploy --processor all
    manage.py lambda rollback --processor all
    manage.py lambda test --processor rule --rules lateral_movement root_logins

""".format(version))
    lambda_parser = subparsers.add_parser(
        'lambda',
        usage=lambda_usage,
        description=lambda_description,
        help=ARGPARSE_SUPPRESS,
        formatter_class=RawTextHelpFormatter
    )

    # Set the name of this parser to 'lambda'
    lambda_parser.set_defaults(command='lambda')

    # Add subcommand options for the lambda sub-parser
    lambda_parser.add_argument(
        'subcommand',
        choices=['deploy', 'rollback', 'test'],
        help=ARGPARSE_SUPPRESS
    )

    # require the name of the processor being deployed/rolled back/tested
    lambda_parser.add_argument(
        '--processor',
        choices=['alert', 'all', 'athena', 'rule'],
        help=ARGPARSE_SUPPRESS,
        action='append',
        required=True
    )

    # allow verbose output for the CLI with the --debug option
    lambda_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )

    # add the optional ability to test against a rule/set of rules
    lambda_parser.add_argument(
        '-r', '--rules',
        nargs='+',
        help=ARGPARSE_SUPPRESS
    )


def _add_terraform_subparser(subparsers):
    """Add Terraform subparser: manage.py terraform [subcommand] [options]"""
    terraform_usage = 'manage.py terraform [subcommand] [options]'
    terraform_description = ("""
StreamAlertCLI v{}
Plan and Apply StreamAlert Infrastructure with Terraform

Available Subcommands:

    manage.py terraform init                   Initialize StreamAlert infrastructure
    manage.py terraform init-backend           Initialize the Terraform backend
    manage.py terraform build [options]        Run Terraform on all StreamAlert modules
    manage.py terraform clean                  Remove Terraform files (only use this when destroying all infrastructure)
    manage.py terraform destroy [options]      Destroy StreamAlert infrastructure
    manage.py terraform generate               Generate Terraform files from JSON cluster files
    manage.py terraform status                 Show cluster health, and other currently configured infrastructure information

Available Options:

    --target                                   The Terraform module name to apply.
                                               Valid options: stream_alert, kinesis, kinesis_events,
                                               cloudtrail, monitoring, and s3_events.
Examples:

    manage.py terraform init
    manage.py terraform init-backend
    manage.py terraform generate

    manage.py terraform build
    manage.py terraform build --target kinesis
    manage.py terraform build --target stream_alert

    manage.py terraform destroy
    manage.py terraform destroy -target cloudtrail

""".format(version))
    tf_parser = subparsers.add_parser(
        'terraform',
        usage=terraform_usage,
        description=terraform_description,
        help=ARGPARSE_SUPPRESS,
        formatter_class=RawTextHelpFormatter
    )

    # set the name of this parser to 'terraform'
    tf_parser.set_defaults(command='terraform')

    # add subcommand options for the terraform sub-parser
    tf_parser.add_argument(
        'subcommand',
        choices=['build',
                 'clean',
                 'destroy',
                 'init',
                 'init-backend',
                 'generate',
                 'status'],
        help=ARGPARSE_SUPPRESS
    )

    tf_parser.add_argument(
        '--target',
        choices=['athena',
                 'cloudwatch_monitoring',
                 'cloudtrail',
                 'flow_logs',
                 'kinesis',
                 'kinesis_events',
                 'stream_alert',
                 's3_events'],
        help=ARGPARSE_SUPPRESS,
        nargs='+'
    )

    tf_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )


def _add_configure_subparser(subparsers):
    """Add configure subparser: manage.py configure [config_key] [config_value]"""
    configure_usage = 'manage.py configure [config_key] [config_value]'
    configure_description = ("""
StreamAlertCLI v{}
Configure StreamAlert options

Available Keys:

    prefix                     Resource prefix
    aws_account_id             AWS account number

Examples:

    manage.py configure prefix my-organization

""".format(version))
    configure_parser = subparsers.add_parser(
        'configure',
        usage=configure_usage,
        description=configure_description,
        help=ARGPARSE_SUPPRESS,
        formatter_class=RawTextHelpFormatter
    )

    configure_parser.set_defaults(command='configure')

    configure_parser.add_argument(
        'config_key',
        choices=['prefix',
                 'aws_account_id'],
        help=ARGPARSE_SUPPRESS
    )

    configure_parser.add_argument(
        'config_value',
        help=ARGPARSE_SUPPRESS
    )

    configure_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )


def _add_athena_subparser(subparsers):
    """Add athena subparser: manage.py athena [subcommand]"""
    athena_usage = 'manage.py athena [subcommand]'
    athena_description = ("""
StreamAlertCLI v{}
Athena StreamAlert options

Available Subcommands:

    manage.py athena init                 Create the Athena base config
    manage.py athena enable               Enable Athena Partition Refresh Lambda function
    manage.py athena create-db            Initialize the Athena Database (streamalert)
    manage.py athena create-table         Create an Athena table

Examples:

    manage.py athena create-db
    manage.py athena create-table --type alerts --bucket s3.bucket.name

""".format(version))
    athena_parser = subparsers.add_parser(
        'athena',
        usage=athena_usage,
        description=athena_description,
        help=ARGPARSE_SUPPRESS,
        formatter_class=RawTextHelpFormatter
    )

    athena_parser.set_defaults(command='athena')

    athena_parser.add_argument(
        'subcommand',
        choices=['init', 'enable', 'create-db', 'create-table'],
        help=ARGPARSE_SUPPRESS
    )

    # TODO(jacknagz): Create a second choice for data tables, and accept a log name argument.
    athena_parser.add_argument(
        '--type',
        choices=['alerts'],
        help=ARGPARSE_SUPPRESS
    )

    athena_parser.add_argument(
        '--bucket',
        help=ARGPARSE_SUPPRESS
    )

    athena_parser.add_argument(
        '--refresh_type',
        choices=['add_hive_partition', 'repair_hive_table'],
        help=argparse_suppress
    )

    athena_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )


def build_parser():
    """Build the argument parser."""
    description = ("""
StreamAlertCLI v{}
Build, Deploy, Configure, and Test StreamAlert Infrastructure

Available Commands:

    manage.py terraform        Manage StreamAlert infrastructure
    manage.py output           Configure new StreamAlert outputs
    manage.py lambda           Deploy, test, and rollback StreamAlert AWS Lambda functions
    manage.py live-test        Send alerts to configured outputs
    manage.py configure        Configure StreamAlert settings

For additional details on the available commands, try:

    manage.py [command] --help

""".format(version))
    usage = '%(prog)s [command] [subcommand] [options]'

    parser = ArgumentParser(
        description=description,
        prog='manage.py',
        usage=usage,
        formatter_class=RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers()
    _add_output_subparser(subparsers)
    _add_live_test_subparser(subparsers)
    _add_lambda_subparser(subparsers)
    _add_terraform_subparser(subparsers)
    _add_configure_subparser(subparsers)
    _add_athena_subparser(subparsers)

    return parser


def main():
    """Entry point for the CLI."""
    parser = build_parser()
    options = parser.parse_args()
    cli_runner(options)
    LOGGER_CLI.info('Completed')


if __name__ == "__main__":
    main()

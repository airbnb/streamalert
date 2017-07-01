#! /usr/bin/env python

'''
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
'''
import os

from argparse import ArgumentParser, RawTextHelpFormatter
from argparse import SUPPRESS as argparse_suppress

from stream_alert_cli.runner import cli_runner
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli import __version__ as version


def build_parser():
    description = ("""
StreamAlertCLI v{}
Build, Deploy, Configure, and Test StreamAlert Infrastructure

Available Commands:

    stream_alert_cli.py terraform               Manage StreamAlert infrastructure
    stream_alert_cli.py output                  Configure new StreamAlert outputs
    stream_alert_cli.py lambda                  Deploy, test, and rollback StreamAlert AWS Lambda functions

For additional details on the available commands, try:

    stream_alert_cli.py [command] --help

""".format(version))
    usage = '%(prog)s [command] [subcommand] [options]'

    parser = ArgumentParser(
        description=description,
        prog='stream_alert_cli.py',
        usage=usage,
        formatter_class=RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers()

    #
    # Output Parser
    #
    output_usage = 'stream_alert_cli.py output [subcommand] [options]'
    output_description = ("""
StreamAlertCLI v{}
Define new StreamAlert outputs to send alerts to

Available Subcommands:

    stream_alert_cli.py output new [options]    Create a new StreamAlert output

Examples:

    stream_alert_cli.py output new --service <service_name>
    stream_alert_cli.py output new --service aws-s3
    stream_alert_cli.py output new --service pagerduty
    stream_alert_cli.py output new --service slack

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
        help=argparse_suppress
    )
    # Output service options
    output_parser.add_argument(
        '--service',
        choices=['aws-lambda', 'aws-s3', 'pagerduty', 'phantom', 'slack'],
        required=True,
        help=argparse_suppress
    )

    #
    # Live Test Parser
    #
    live_test_usage = 'stream_alert_cli.py live-test [options]'
    live_test_description = ("""
StreamAlertCLI v{}
Run end-to-end tests that will attempt to send alerts

Available Options:

    --cluster               The cluster name to use for live testing
    --rules                 Name of rules to test, separated by spaces
    --debug                 Enable Debug logger output

Examples:

    stream_alert_cli.py live-test --cluster prod
    stream_alert_cli.py live-test --rules

""".format(version))
    live_test_parser = subparsers.add_parser(
        'live-test',
        description=live_test_description,
        usage=live_test_usage,
        formatter_class=RawTextHelpFormatter,
        help=argparse_suppress
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
        help=argparse_suppress,
        required=True
    )

    # add the optional ability to test against a rule/set of rules
    live_test_parser.add_argument(
        '-r', '--rules',
        nargs='+',
        help=argparse_suppress
    )

    # allow verbose output for the CLI with te --debug option
    live_test_parser.add_argument(
        '--debug',
        action='store_true',
        help=argparse_suppress
    )

    #
    # Lambda Parser
    #
    lambda_usage = 'stream_alert_cli.py lambda [subcommand] [options]'
    lambda_description = ("""
StreamAlertCLI v{}
Deploy, Rollback, and Test StreamAlert Lambda functions

Available Subcommands:

    stream_alert_cli.py lambda deploy [options]         Deploy Lambda functions
    stream_alert_cli.py lambda rollback [options]       Rollback Lambda functions
    stream_alert_cli.py lambda test [options]           Run rule tests

Available Options:

    --processor                                         The name of the Lambda function to manage.
                                                        Valid options include: rule, alert, or all.
    --debug                                             Enable Debug logger output.
    --rules                                             List of rules to test, separated by spaces.

Examples:

    stream_alert_cli.py lambda deploy --processor all
    stream_alert_cli.py lambda rollback --processor all
    stream_alert_cli.py lambda test --processor rule --rules lateral_movement root_logins

""".format(version))
    lambda_parser = subparsers.add_parser(
        'lambda',
        usage=lambda_usage,
        description=lambda_description,
        help=argparse_suppress,
        formatter_class=RawTextHelpFormatter
    )

    # Set the name of this parser to 'lambda'
    lambda_parser.set_defaults(command='lambda')

    # Add subcommand options for the lambda sub-parser
    lambda_parser.add_argument(
        'subcommand',
        choices=['deploy', 'rollback', 'test'],
        help=argparse_suppress
    )

    # require the name of the processor being deployed/rolled back/tested
    lambda_parser.add_argument(
        '--processor',
        choices=['alert', 'all', 'rule'],
        help=argparse_suppress,
        required=True
    )

    # allow verbose output for the CLI with te --debug option
    lambda_parser.add_argument(
        '--debug',
        action='store_true',
        help=argparse_suppress
    )

    # add the optional ability to test against a rule/set of rules
    lambda_parser.add_argument(
        '-r', '--rules',
        nargs='+',
        help=argparse_suppress
    )

    #
    # Terraform Parser
    #
    terraform_usage = 'stream_alert_cli.py terraform [subcommand] [options]'
    terraform_description = ("""
StreamAlertCLI v{}
Plan and Apply StreamAlert Infrastructure with Terraform

Available Subcommands:

    stream_alert_cli.py terraform init                      Initialize StreamAlert infrastructure
    stream_alert_cli.py terraform init-backend              Initialize the Terraform backend
    stream_alert_cli.py terraform build [options]           Run Terraform on all StreamAlert modules
    stream_alert_cli.py terraform clean                     Remove Terraform files (only use this when destroying all infrastructure)
    stream_alert_cli.py terraform destroy [options]         Destroy StreamAlert infrastructure
    stream_alert_cli.py terraform generate                  Generate Terraform files from JSON cluster files
    stream_alert_cli.py terraform status                    Show cluster health, and other currently configured infrastructure information

Available Options:

    --target                                                The Terraform module name to apply.
                                                            Valid options: stream_alert, kinesis, kinesis_events,
                                                            cloudtrail, monitoring, and s3_events.
Examples:

    stream_alert_cli.py terraform init
    stream_alert_cli.py terraform init-backend
    stream_alert_cli.py terraform generate

    stream_alert_cli.py terraform build
    stream_alert_cli.py terraform build --target kinesis
    stream_alert_cli.py terraform build --target stream_alert

    stream_alert_cli.py terraform destroy
    stream_alert_cli.py terraform destroy -target cloudtrail

""".format(version))
    tf_parser = subparsers.add_parser(
        'terraform',
        usage=terraform_usage,
        description=terraform_description,
        help=argparse_suppress,
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
        help=argparse_suppress
    )

    tf_parser.add_argument(
        '--target',
        choices=['stream_alert',
                'kinesis',
                'kinesis_events',
                's3_events',
                'cloudwatch_monitoring'
                'cloudtrail',
                'flow_logs'],
        help=argparse_suppress,
        nargs='+'
    )

    return parser


def main():
    parser = build_parser()
    options = parser.parse_args()
    cli_runner(options)
    LOGGER_CLI.info('Completed')


if __name__ == "__main__":
    main()

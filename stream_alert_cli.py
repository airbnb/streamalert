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

from stream_alert_cli.runner import cli_runner
from stream_alert_cli.logger import LOGGER_CLI


def build_parser():
    description = (
        """Build, Deploy, and Test StreamAlert Infrastructure

    Define New Outputs:
    stream_alert_cli.py output new --service 'service_name'

    Deploying Lambda Functions:
    stream_alert_cli.py lambda deploy --processor 'rule'
    stream_alert_cli.py lambda deploy --processor 'alert'
    stream_alert_cli.py lambda deploy --processor 'all'

    Rolling Back:
    stream_alert_cli.py lambda rollback --processor 'rule'

    Running Integration Tests:
    stream_alert_cli.py lambda test --processor 'rule'
    stream_alert_cli.py lambda test --processor 'alert'
    stream_alert_cli.py lambda test --processor 'all'

    Building Infrastructure:
    stream_alert_cli.py terraform init
    stream_alert_cli.py terraform build
    stream_alert_cli.py terraform build --target kinesis
    stream_alert_cli.py terraform build --target stream_alert
    """
    )

    parser = ArgumentParser(
        description=description,
        prog='stream_alert_cli.py',
        formatter_class=RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers()

    # defining new outputs
    output_parser = subparsers.add_parser(
        'output',
        help='Define a new output to send alerts to'
    )

    # set the name of this parser to 'output'
    output_parser.set_defaults(command='output')

    # output parser arguments. the cli will handle the logic to set these up
    output_parser.add_argument(
        'subcommand',
        choices=['new'],
        help=('new: create a new output to send alerts to\n')
    )
    # output service options
    output_parser.add_argument(
        '--service',
        choices=['aws-lambda', 'aws-s3', 'pagerduty', 'phantom', 'slack'],
        help='The name of the service to send alerts to',
        required=True
    )

    # live-test parser
    live_test_parser = subparsers.add_parser(
        'live-test',
        help='Run end-to-end tests that will attempt to send alerts'
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
        help='Specific cluster to use for live testing',
        required=True
    )

    # add the optional ability to test against a rule/set of rules
    live_test_parser.add_argument(
        '-r', '--rules',
        nargs='+',
        help='Names of rules to test, separated by spaces'
    )

    # allow verbose output for the CLI with te --debug option
    live_test_parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable DEBUG logger output'
    )

    # lambda parser
    lambda_parser = subparsers.add_parser(
        'lambda',
        help='Deploy, Rollback, and Test StreamAlert Lambda functions'
    )

    # set the name of this parser to 'lambda'
    lambda_parser.set_defaults(command='lambda')

    # add subcommand options for the lambda sub-parser
    lambda_parser.add_argument(
        'subcommand',
        choices=['deploy', 'rollback', 'test'],
        help=('deploy: Build Lambda package, upload to S3, and deploy with Terraform\n'
              'rollback: Roll a Lambda function back by one production vpersion\n'
              'test: Run integration tests on a Lambda function')
    )

    # require the name of the processor being deployed/rolled back/tested
    lambda_parser.add_argument(
        '--processor',
        choices=['alert', 'all', 'rule'],
        help='The name of the AWS Lambda function to deploy, rollback, or test',
        required=True
    )

    # allow verbose output for the CLI with te --debug option
    lambda_parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable DEBUG logger output'
    )

    # add the optional ability to test against a rule/set of rules
    lambda_parser.add_argument(
        '-r', '--rules',
        nargs='+',
        help='Names of rules to test, separated by spaces'
    )

    # terraform parser and defaults
    tf_parser = subparsers.add_parser(
        'terraform',
        help='Build the stream alert infrastructure'
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
                 'status']
    )

    tf_parser.add_argument(
        '--target',
        choices=['stream_alert', 'kinesis', 'kinesis_events', 's3_events',
                 'cloudwatch_monitoring'],
        help='A specific Terraform module to build',
        nargs='?'
    )

    return parser


def main():
    parser = build_parser()
    options = parser.parse_args()
    cli_runner(options)
    LOGGER_CLI.info('Completed')


if __name__ == "__main__":
    main()

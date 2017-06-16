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
    stream_alert_cli.py lambda rollback --func 'rule'

    Running Integration Tests:
    stream_alert_cli.py lambda test --processor 'rule'
    stream_alert_cli.py lambda test --processor 'alert'

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
    output_parser.set_defaults(
        command='output'
    )

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

    # lambda parser and defaults
    lambda_parser = subparsers.add_parser(
        'lambda',
        help='Deploy, Rollback, and Test StreamAlert Lambda functions'
    )
    lambda_parser.set_defaults(
        command='lambda'
    )

    # lambda parser arguments
    lambda_parser.add_argument(
        'subcommand',
        choices=['deploy', 'rollback', 'test'],
        help=('Deploy: Build Lambda package, upload to S3, and deploy with Terraform\n'
              'Rollback: Roll a Lambda function back by one production vpersion\n'
              'Test: Run integration tests on a Lambda function')
    )
    lambda_parser.add_argument(
        '--processor',
        choices=['alert', 'all', 'rule'],
        help='The name of the AWS Lambda function to deploy',
        required=True
    )
    lambda_parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable DEBUG logger output'
    )

    lambda_parser.add_argument(
        '-r', '--rules',
        nargs='+',
        help='Names of rules to test, separated by spaces'
    )

    lambda_parser.add_argument(
        '-l', '--live',
        help='Run end-to-end tests in the specified cluster'
    )

    # terraform parser and defaults
    tf_parser = subparsers.add_parser(
        'terraform',
        help='Build the stream alert infrastructure'
    )
    tf_parser.add_argument(
        'subcommand',
        choices=['build', 'destroy', 'init', 'init-backend', 'generate', 'status']
    )
    tf_parser.add_argument(
        '--target',
        choices=['stream_alert', 'kinesis', 'kinesis_events', 's3_events',
                 'cloudwatch_monitoring'],
        help='A specific Terraform module to build',
        nargs='?'
    )
    tf_parser.set_defaults(command='terraform')

    return parser


def main():
    parser = build_parser()
    options = parser.parse_args()
    cli_runner(options)
    LOGGER_CLI.info('Completed')


if __name__ == "__main__":
    main()

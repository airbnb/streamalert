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

import logging
from argparse import ArgumentParser, RawTextHelpFormatter

from stream_alert_cli.runner import cli_runner

def build_parser():
    description = (
    """Build, Deploy, and Test StreamAlert Infrastructure

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
        choices=['deploy',
                 'rollback',
                 'test'],
        help=('Deploy: Build Lambda package, upload to S3, and deploy with Terraform\n'
              'Rollback: Roll a Lambda function back by one production vpersion\n'
              'Test: Run integration tests on a Lambda function')
    )
    lambda_parser.add_argument(
        '--processor',
        choices=['rule',
                 'alert',
                 'all'],
        help='The name of the AWS Lambda function to deploy',
        required=True
    )
    lambda_parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable DEBUG logger output'
    )

    # terraform parser and defaults
    tf_parser = subparsers.add_parser(
        'terraform',
        help='Build the stream alert infrastructure'
    )
    tf_parser.add_argument(
        'subcommand',
        choices=['build',
                 'init',
                 'destroy',
                 'status',
                 'generate']
    )
    tf_parser.add_argument(
        '--target',
        choices=['stream_alert',
                 'kinesis',
                 'kinesis_events',
                 's3_events',
                 'cloudwatch_monitoring'],
        help='A specific Terraform module to build',
        nargs='?'
    )
    tf_parser.set_defaults(command='terraform')

    return parser

def main():
    # logging.basicConfig(level=logging.INFO,
    #                     format='%(asctime)s [%(levelname)s] %(message)s',
    #                     datefmt='%m/%d/%Y %I:%M:%S%p')
    parser = build_parser()
    options = parser.parse_args()
    cli_runner(options)
    logging.info('Completed')

if __name__ == "__main__": main()

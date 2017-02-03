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
deploying to AWS Lambda, and publishing versions from staging to production.

To run terraform by hand, cd to the terraform/ directory and run:
    terraform <cmd> -var-file=../terraform.tfvars -var-file=../variables.json
'''

import logging
from argparse import ArgumentParser, RawTextHelpFormatter
from stream_alert_cli.cli import StreamAlertCLI

def build_parser():
    description = (
    """
CLI tool to build and deploy StreamAlert infrastructure and lambda code.

Examples:
    stream_alert_cli.py lambda deploy --env 'staging' --func 'alert'
    stream_alert_cli.py lambda deploy --env 'production' --func 'alert'
    stream_alert_cli.py lambda deploy --env 'staging' --func '*'
    
    stream_alert_cli.py lambda rollback --env 'production' --func 'alert'
    
    stream_alert_cli.py terraform init
    stream_alert_cli.py terraform build
    stream_alert_cli.py terraform build --target kinesis
    
    stream_alert_cli.py lambda test --func 'alert' --source s3
    stream_alert_cli.py lambda test --func 'output' --source kinesis
    """
    )

    parser = ArgumentParser(
        description=description,
        prog='stream_alert_cli.py',
        formatter_class=RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(help='All commands')

    lambda_parser = subparsers.add_parser(
        'lambda',
        help='Manage the stream alert lambda function'
    )
    lambda_parser.set_defaults(
        command='lambda',
        env='staging',
        source='kinesis'
    )

    lambda_parser.add_argument(
        'subcommand',
        choices=['deploy','rollback', 'test'],
        help='''deploy -- Upload to S3 and update Terraform config
                rollback -- Roll the production lambda back one version.'''
    )
    lambda_parser.add_argument(
        '--source',
        choices=['s3', 'kinesis'],
        help='the test fixture source.'
    )
    lambda_parser.add_argument(
        '--env',
        choices=['staging', 'production'],
        help='the environment to deploy the lambda function to.'
    )
    lambda_parser.add_argument(
        '--func',
        choices=['alert', 'output', '*'],
        help='the name of the lambda function to deploy.',
        required=True
    )

    tf_parser = subparsers.add_parser(
        'terraform',
        help='Build the stream alert infrastructure'
    )
    tf_parser.add_argument(
        'subcommand',
        choices=['build', 'init', 'destroy', 'status', 'generate']
    )
    tf_parser.add_argument(
        '--target',
        choices=['stream_alert',
                 'kinesis',
                 'kinesis_events',
                 's3_events',
                 'cloudwatch_monitoring'],
        help='the target to apply the Terraform command to.',
        nargs='?'
    )
    tf_parser.set_defaults(command='terraform')

    return parser

def main():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s [%(levelname)s] %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S%p')
    parser = build_parser()
    options = parser.parse_args()
    cli = StreamAlertCLI()
    cli.run(options)
    logging.info('Completed')

if __name__ == "__main__": main()

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
from stream_alert_cli.config import CLIConfig
from stream_alert_cli.manage_lambda.deploy import deploy
from stream_alert_cli.manage_lambda.rollback import rollback
from stream_alert_cli.test import stream_alert_test
from stream_alert_cli.terraform.generate import terraform_generate


CONFIG = CLIConfig()

def lambda_handler(options):
    """Handle all Lambda CLI operations"""

    if options.subcommand == 'deploy':
        # Make sure the Terraform code is up to date
        if not terraform_generate(config=CONFIG):
            return
        deploy(options)

    elif options.subcommand == 'rollback':
        # Make sure the Terraform code is up to date
        if not terraform_generate(config=CONFIG):
            return
        rollback(options)

    elif options.subcommand == 'test':
        stream_alert_test(options)

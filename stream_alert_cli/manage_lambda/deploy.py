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
import sys

from app_integrations import __version__ as apps_version
from stream_alert import __version__ as current_version
from stream_alert_cli import helpers
from stream_alert_cli.manage_lambda.package import (AlertProcessorPackage, AthenaPackage,
                                                    AppIntegrationPackage, RuleProcessorPackage)
from stream_alert_cli.terraform.generate import terraform_generate
from stream_alert_cli.version import LambdaVersion


def deploy(options, config):
    """Deploy new versions of all Lambda functions

    Steps:
    - Build AWS Lambda deployment package
    - Upload to S3
    - Update lambda.json with uploaded package checksum and S3 key
    - Publish new version
    - Update each cluster's Lambda configuration with latest published version
    - Run Terraform Apply
    """
    processor = options.processor
    # Terraform apply only to the module which contains our lambda functions
    targets = set()
    packages = []

    def _publish_version(packages):
        """Publish Lambda versions"""
        for package in packages:
            if package.package_name == 'athena_partition_refresh':
                published = LambdaVersion(
                    config=config, package=package, clustered_deploy=False).publish_function()
            else:
                published = LambdaVersion(config=config, package=package).publish_function()
            if not published:
                return False

        return True

    def _deploy_rule_processor():
        """Create Rule Processor package and publish versions"""
        rule_package = RuleProcessorPackage(config=config, version=current_version)
        rule_package.create_and_upload()
        return rule_package

    def _deploy_alert_processor():
        """Create Alert Processor package and publish versions"""
        alert_package = AlertProcessorPackage(config=config, version=current_version)
        alert_package.create_and_upload()
        return alert_package

    def _deploy_athena_partition_refresh():
        """Create Athena Partition Refresh package and publish"""
        athena_package = AthenaPackage(config=config, version=current_version)
        athena_package.create_and_upload()
        return athena_package

    def _deploy_apps_function():
        """Create app integration package and publish versions"""
        app_integration_package = AppIntegrationPackage(config=config, version=apps_version)
        app_integration_package.create_and_upload()
        return app_integration_package

    if 'all' in processor:
        targets.update({'module.stream_alert_{}'.format(x) for x in config.clusters()})

        targets.update({
            'module.app_{}_{}'.format(app_name, cluster)
            for cluster, info in config['clusters'].iteritems()
            for app_name in info['modules'].get('stream_alert_apps', {})
        })

        packages.append(_deploy_rule_processor())
        packages.append(_deploy_alert_processor())
        packages.append(_deploy_apps_function())

        # Only include the Athena function if it exists and is enabled
        athena_config = config['lambda'].get('athena_partition_refresh_config')
        if athena_config and athena_config.get('enabled', False):
            targets.add('module.stream_alert_athena')
            packages.append(_deploy_athena_partition_refresh())

    else:

        if 'rule' in processor:
            targets.update({'module.stream_alert_{}'.format(x) for x in config.clusters()})

            packages.append(_deploy_rule_processor())

        if 'alert' in processor:
            targets.update({'module.stream_alert_{}'.format(x) for x in config.clusters()})

            packages.append(_deploy_alert_processor())

        if 'apps' in processor:

            targets.update({
                'module.app_{}_{}'.format(app_name, cluster)
                for cluster, info in config['clusters'].iteritems()
                for app_name in info['modules'].get('stream_alert_apps', {})
            })

            packages.append(_deploy_apps_function())

        if 'athena' in processor:
            targets.add('module.stream_alert_athena')

            packages.append(_deploy_athena_partition_refresh())

    # Regenerate the Terraform configuration with the new S3 keys
    if not terraform_generate(config=config):
        return

    # Run Terraform: Update the Lambda source code in $LATEST
    if not helpers.tf_runner(targets=targets):
        sys.exit(1)

    # TODO(jack) write integration test to verify newly updated function

    # Publish a new production Lambda version
    if not _publish_version(packages):
        return

    # Regenerate the Terraform configuration with the new Lambda versions
    if not terraform_generate(config=config):
        return

    # Apply the changes to the Lambda aliases
    helpers.tf_runner(targets=targets, refresh_state=False)

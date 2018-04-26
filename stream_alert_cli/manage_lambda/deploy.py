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
from collections import namedtuple
import sys

from stream_alert.shared import rule_table
from stream_alert_cli import helpers
from stream_alert_cli.manage_lambda import package as stream_alert_packages
from stream_alert_cli.manage_lambda.version import LambdaVersion
from stream_alert_cli.terraform.generate import terraform_generate


PackageMap = namedtuple('package_attrs', ['package_class', 'targets', 'enabled'])


def _publish_version(packages, config, clusters):
    """Publish production Lambda versions

    Args:
        packages (list[LambdaPackage])
        config (CLIConfig)
        clusters (set)

    Returns:
        bool: Result of Lambda version publishing
    """
    global_packages = {
        'alert_merger', 'alert_processor', 'athena_partition_refresh', 'threat_intel_downloader'
    }

    for package in packages:
        if package.package_name in global_packages:
            published = LambdaVersion(
                config=config, package=package).publish_function(clustered_deploy=False)
        else:
            published = LambdaVersion(
                config=config, package=package).publish_function(clustered_deploy=True,
                                                                 clusters=clusters)
        if not published:
            return False

    return True


def _update_rule_table(options, config):
    """Update the rule table with any staging information

    Args:
        options (argparser.Namespace): Various options from the CLI needed for actions
        config (CLIConfig): The loaded StreamAlert config
    """
    # TODO: consider removing this once rule staging is feature complete
    # Temporarily having a config setting that will disable updating the table for now
    if not config['global']['infrastructure']['rules_table'].get('enabled', False):
        return

    # Get the rule import paths to load
    rule_import_paths = config['global']['general']['rule_locations']

    table_name = '{}_streamalert_rules'.format(config['global']['account']['prefix'])
    table = rule_table.RuleTable(table_name, *rule_import_paths)
    table.update(options.skip_rule_staging)

    if options.stage_rules or options.unstage_rules:
        # Create a dictionary of rule_name: stage=True|False
        rules = {rule_name: False for rule_name in options.unstage_rules}
        rules.update({rule_name: True for rule_name in options.stage_rules})
        for rule, stage in rules.iteritems():
            table.toggle_staged_state(rule, stage)


def _create_and_upload(function_name, config, cluster=None):
    """
    Args:
        function_name: The name of the function to create and upload
        config (CLIConfig): The loaded StreamAlert config
        cluster (string): The cluster to deploy to

    Returns:
        tuple (LambdaPackage, set): The created Lambda package and the set of Terraform targets
    """
    clusters = cluster or config.clusters()

    package_mapping = {
        'alert': PackageMap(
            stream_alert_packages.AlertProcessorPackage,
            {'module.alert_processor_lambda'},
            True
        ),
        'alert_merger': PackageMap(
            stream_alert_packages.AlertMergerPackage,
            {'module.alert_merger_lambda'},
            True
        ),
        'apps': PackageMap(
            stream_alert_packages.AppIntegrationPackage,
            {'module.app_{}_{}_lambda'.format(app_info['app_name'], cluster)
             for cluster, info in config['clusters'].iteritems()
             for app_info in info['modules'].get('stream_alert_apps', {}).values()
             if 'app_name' in app_info},
            True
        ),
        'athena': PackageMap(
            stream_alert_packages.AthenaPackage,
            {'module.stream_alert_athena'},
            True
        ),
        'rule': PackageMap(
            stream_alert_packages.RuleProcessorPackage,
            {'module.stream_alert_{}'.format(cluster) for cluster in clusters},
            True
        ),
        'threat_intel_downloader': PackageMap(
            stream_alert_packages.ThreatIntelDownloaderPackage,
            {'module.threat_intel_downloader'},
            config['lambda'].get('threat_intel_downloader_config', False)
        )
    }

    if not package_mapping[function_name].enabled:
        return False, False

    package = package_mapping[function_name].package_class(config=config)
    success = package.create_and_upload()

    if not success:
        sys.exit(1)

    return package, package_mapping[function_name].targets


def deploy(options, config):
    """Deploy new versions of all Lambda functions

    Args:
        options (namedtuple): ArgParsed command from the CLI
        config (CLIConfig): Loaded StreamAlert config

    Steps:
        Build AWS Lambda deployment package
        Upload to S3
        Update lambda.json with uploaded package checksum and S3 key
        Publish new version
        Update each cluster's Lambda configuration with latest published version
        Run Terraform Apply
    """
    # Terraform apply only to the module which contains our lambda functions
    deploy_targets = set()
    packages = []

    if 'all' in options.processor:
        processors = {'alert', 'alert_merger', 'apps', 'athena', 'rule', 'threat_intel_downloader'}
    else:
        processors = options.processor

    for processor in processors:
        package, targets = _create_and_upload(processor, config, options.clusters)
        # Continue if the package isn't enabled
        if not all([package, targets]):
            continue

        packages.append(package)
        deploy_targets.update(targets)

    # Regenerate the Terraform configuration with the new S3 keys
    if not terraform_generate(config=config):
        return

    # Run Terraform: Update the Lambda source code in $LATEST
    if not helpers.tf_runner(targets=deploy_targets):
        sys.exit(1)

    # Update the rule table now if the rule processor is being deployed
    if 'rule' in options.processor:
        _update_rule_table(options, config)

    # Publish a new production Lambda version
    if not _publish_version(packages, config, options.clusters):
        return

    # Regenerate the Terraform configuration with the new Lambda versions
    if not terraform_generate(config=config):
        return

    # Apply the changes to the Lambda aliases
    helpers.tf_runner(targets=deploy_targets, refresh=False, auto_approve=True)

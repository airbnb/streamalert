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
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.manage_lambda import package as stream_alert_packages

PackageMap = namedtuple('package_attrs', ['package_class', 'targets', 'enabled'])


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
            if rule not in table.remote_rule_info:
                LOGGER_CLI.error(
                    'Staging status for rule \'%s\' cannot be set to %s; rule does not exist',
                    stage, rule
                )
                continue
            if table.remote_rule_info[rule]['Staged'] and stage:
                LOGGER_CLI.info(
                    'Rule \'%s\' is already staged and will have its staging window updated',
                    rule
                )
            table.toggle_staged_state(rule, stage)


def _create(function_name, config, cluster=None):
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
            {'module.alert_processor_iam', 'module.alert_processor_lambda'},
            True
        ),
        'alert_merger': PackageMap(
            stream_alert_packages.AlertMergerPackage,
            {'module.alert_merger_iam', 'module.alert_merger_lambda'},
            True
        ),
        'apps': PackageMap(
            stream_alert_packages.AppIntegrationPackage,
            {'module.app_{}_{}_{}'.format(app_info['app_name'], cluster, suffix)
             for suffix in {'lambda', 'iam'}
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
    success = package.create()

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
        package, targets = _create(processor, config, options.clusters)
        # Continue if the package isn't enabled
        if not all([package, targets]):
            continue

        packages.append(package)
        deploy_targets.update(targets)

    # Update the rule table now if the rule processor is being deployed
    if 'rule' in options.processor:
        _update_rule_table(options, config)

    # Terraform applies the new package and publishes a new version
    helpers.tf_runner(targets=deploy_targets)

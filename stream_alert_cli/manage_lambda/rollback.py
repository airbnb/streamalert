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
from stream_alert_cli.logger import LOGGER_CLI

import boto3
from botocore.exceptions import ClientError


def _rollback_production(lambda_client, function_name):
    """Rollback the production alias for the given function name."""
    version = lambda_client.get_alias(
        FunctionName=function_name, Name='production')['FunctionVersion']

    if version == '$LATEST':
        # This won't happen with Terraform, but the alias could have been manually changed.
        LOGGER_CLI.error('%s:production is pointing to $LATEST instead of a published version',
                         function_name)
        return

    current_version = int(version)
    if current_version == 1:
        LOGGER_CLI.warn('%s:production is already at version 1', function_name)
        return

    LOGGER_CLI.info('Rolling back %s:production from version %d => %d',
                    function_name, current_version, current_version - 1)
    try:
        lambda_client.update_alias(
            FunctionName=function_name, Name='production', FunctionVersion=str(current_version - 1))
    except ClientError:
        LOGGER_CLI.exception('version not updated')


def rollback(options, config):
    """Rollback the current production Lambda version(s) by 1.

    Args:
        options: Argparse parsed options
        config (dict): Parsed configuration from conf/
    """
    rollback_all = 'all' in options.processor
    prefix = config['global']['account']['prefix']
    clusters = sorted(options.clusters or config.clusters())
    client = boto3.client('lambda')

    if rollback_all or 'alert' in options.processor:
        _rollback_production(client, '{}_streamalert_alert_processor'.format(prefix))

    if rollback_all or 'alert_merger' in options.processor:
        _rollback_production(client, '{}_streamalert_alert_merger'.format(prefix))

    if rollback_all or 'apps' in options.processor:
        for cluster in clusters:
            apps_config = config['clusters'][cluster]['modules'].get('stream_alert_apps', {})
            for lambda_name in sorted(apps_config):
                _rollback_production(client, lambda_name)

    if rollback_all or 'athena' in options.processor:
        _rollback_production(client, '{}_streamalert_athena_partition_refresh'.format(prefix))

    if rollback_all or 'rule' in options.processor:
        for cluster in clusters:
            _rollback_production(client, '{}_{}_streamalert_rule_processor'.format(prefix, cluster))

    if rollback_all or 'threat_intel_downloader' in options.processor:
        _rollback_production(client, '{}_streamalert_threat_intel_downloader'.format(prefix))

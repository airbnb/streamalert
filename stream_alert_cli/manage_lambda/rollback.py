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
from stream_alert_cli import helpers
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.terraform.generate import terraform_generate


def _decrement_version(lambda_config):
    """Decrement the Lambda version, if possible.

    Args:
        lambda_config (dict): Lambda function config with 'current_version'

    Returns:
        True if the version was changed, False otherwise
    """
    current_version = lambda_config['current_version']
    if current_version == '$LATEST':
        return False

    int_version = int(current_version)
    if int_version <= 1:
        return False

    lambda_config['current_version'] = int_version - 1
    return True


def _try_decrement_version(lambda_config, function_name):
    """Log a warning if the lambda version cannot be rolled back."""
    changed = _decrement_version(lambda_config)
    if not changed:
        LOGGER_CLI.warn('%s cannot be rolled back from version %s',
                        function_name, str(lambda_config['current_version']))
    return changed


def _rollback_alert(config):
    """Decrement the current_version for the alert processor."""
    lambda_config = config['lambda']['alert_processor_config']
    if _try_decrement_version(lambda_config, 'alert_processor'):
        return ['module.alert_processor_lambda']


def _rollback_alert_merger(config):
    """Decrement the current_version for the alert merger."""
    lambda_config = config['lambda']['alert_merger_config']
    if _try_decrement_version(lambda_config, 'alert_merger'):
        return ['module.alert_merger_lambda']


def _rollback_apps(config, clusters):
    """Decrement the current_version for all of the apps functions in the given clusters."""
    tf_targets = []

    for cluster in clusters:
        apps_config = config['clusters'][cluster]['modules'].get('stream_alert_apps', {})
        for lambda_name, lambda_config in apps_config.iteritems():
            if _try_decrement_version(lambda_config, lambda_name):
                module_prefix = 'app_{}_{}'.format(lambda_config['app_name'], cluster)
                tf_targets.append('module.{}'.format(module_prefix))

    return tf_targets


def _rollback_athena(config):
    """Decrement the current_version for the Athena Partition Refresh function."""
    lambda_config = config['lambda'].get('athena_partition_refresh_config')
    if lambda_config and _try_decrement_version(lambda_config, 'athena_partition_refresh'):
        return['module.stream_alert_athena']


def _rollback_downloader(config):
    """Decrement the current_version for the Threat Intel Downloader function."""
    lambda_config = config['lambda'].get('threat_intel_downloader_config')
    if lambda_config and _try_decrement_version(lambda_config, 'threat_intel_downloader_config'):
        return['module.threat_intel_downloader']


def _rollback_rule(config, clusters):
    """Decrement the current_version for the Rule Processor in each of the given clusters"""
    tf_targets = []
    for cluster in clusters:
        lambda_config = config['clusters'][cluster]['modules']['stream_alert']['rule_processor']
        if _try_decrement_version(lambda_config, 'rule_processor_{}'.format(cluster)):
            tf_targets.append('module.stream_alert_{}'.format(cluster))
    return tf_targets


def rollback(options, config):
    """Rollback the current production AWS Lambda version by 1

    Notes:
        Ignores if the production version is $LATEST
        Only rollsback if published version is greater than 1
    """
    clusters = options.clusters or config.clusters()
    rollback_all = 'all' in options.processor
    tf_targets = []

    if rollback_all or 'alert' in options.processor:
        tf_targets.extend(_rollback_alert(config) or [])

    if rollback_all or 'alert_merger' in options.processor:
        tf_targets.extend(_rollback_alert_merger(config) or [])

    if rollback_all or 'apps' in options.processor:
        tf_targets.extend(_rollback_apps(config, clusters) or [])

    if rollback_all or 'athena' in options.processor:
        tf_targets.extend(_rollback_athena(config) or [])

    if rollback_all or 'rule' in options.processor:
        tf_targets.extend(_rollback_rule(config, clusters) or [])

    if rollback_all or 'threat_intel_downloader' in options.processor:
        tf_targets.extend(_rollback_downloader(config) or [])

    if not tf_targets:  # No changes made
        return

    config.write()

    if not terraform_generate(config=config):
        return

    helpers.tf_runner(targets=sorted(tf_targets))

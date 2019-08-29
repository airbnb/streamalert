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
import boto3
from botocore.exceptions import ClientError

from stream_alert.shared.logger import get_logger
from stream_alert_cli.terraform.generate import terraform_generate_handler
from stream_alert_cli.utils import add_default_lambda_args, set_parser_epilog, CliCommand

LOGGER = get_logger(__name__)


class RollbackCommand(CliCommand):

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the rollback subparser: manage.py rollback [options]"""
        set_parser_epilog(
            subparser,
            epilog=(
                '''\
                Example:

                    manage.py rollback --function rule
                '''
            )
        )

        add_default_lambda_args(subparser)

    @classmethod
    def handler(cls, options, config):
        """Rollback the current production Lambda version(s) by 1.

        Args:
            options: Argparse parsed options
            config (dict): Parsed configuration from conf/

        Returns:
            bool: False if errors occurred, True otherwise
        """
        # Make sure the Terraform code is up to date
        if not terraform_generate_handler(config=config):
            return False

        LOGGER.info('Rolling back: %s', ' '.join(options.function))

        rollback_all = 'all' in options.function
        prefix = config['global']['account']['prefix']
        clusters = sorted(options.clusters or config.clusters())
        client = boto3.client('lambda')

        # Track the success of rolling back the functions
        success = True
        if rollback_all or 'alert' in options.function:
            success = success and _rollback_production(
                client,
                '{}_streamalert_alert_processor'.format(prefix)
            )

        if rollback_all or 'alert_merger' in options.function:
            success = success and _rollback_production(
                client,
                '{}_streamalert_alert_merger'.format(prefix)
            )

        if rollback_all or 'apps' in options.function:
            for cluster in clusters:
                apps_config = config['clusters'][cluster]['modules'].get('stream_alert_apps', {})
                for lambda_name in sorted(apps_config):
                    success = success and _rollback_production(client, lambda_name)

        if rollback_all or 'athena' in options.function:
            success = success and _rollback_production(
                client,
                '{}_streamalert_athena_partition_refresh'.format(prefix)
            )

        if rollback_all or 'classifier' in options.function:
            for cluster in clusters:
                success = success and _rollback_production(
                    client,
                    '{}_streamalert_classifier_{}'.format(prefix, cluster)
                )

        if rollback_all or 'rule' in options.function:
            success = success and _rollback_production(
                client, '{}_streamalert_rules_engine'.format(prefix)
            )

        if rollback_all or 'threat_intel_downloader' in options.function:
            success = success and _rollback_production(
                client,
                '{}_streamalert_threat_intel_downloader'.format(prefix)
            )

        return success


def _rollback_production(lambda_client, function_name):
    """Rollback the production alias for the given function name.

    Args:
        lambda_client (boto3.client): boto3 client to use for rolling back the function
        function_name (str): Name of function to be rolled back

    Returns:
        bool: False if errors occurred, True otherwise
    """
    version = lambda_client.get_alias(
        FunctionName=function_name, Name='production')['FunctionVersion']

    if version == '$LATEST':
        # This won't happen with Terraform, but the alias could have been manually changed.
        LOGGER.error('%s:production is pointing to $LATEST instead of a published version',
                     function_name)
        return False

    current_version = int(version)
    if current_version == 1:
        LOGGER.warn('%s:production is already at version 1', function_name)
        return False

    LOGGER.info('Rolling back %s:production from version %d => %d',
                function_name, current_version, current_version - 1)
    try:
        lambda_client.update_alias(
            FunctionName=function_name, Name='production', FunctionVersion=str(current_version - 1))
    except ClientError:
        LOGGER.exception('version not updated')
        return False

    return True




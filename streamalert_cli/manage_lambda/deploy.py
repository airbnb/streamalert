"""
Copyright 2017-present Airbnb, Inc.

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
from streamalert.shared import rule_table
from streamalert.shared.logger import get_logger
from streamalert_cli.terraform.generate import terraform_generate_handler
from streamalert_cli.terraform.helpers import terraform_runner
from streamalert_cli.utils import (CLICommand, MutuallyExclusiveStagingAction,
                                   add_default_lambda_args, set_parser_epilog)

LOGGER = get_logger(__name__)


class DeployCommand(CLICommand):
    description = 'Deploy the specified AWS Lambda function(s)'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the deploy subparser: manage.py deploy [options]"""
        set_parser_epilog(subparser,
                          epilog=('''\
                Example:

                    manage.py deploy --function rule alert
                '''))

        # Flag to manually bypass rule staging for new rules upon deploy
        # This only has an effect if rule staging is enabled
        subparser.add_argument('--skip-rule-staging',
                               action='store_true',
                               help='Skip staging of new rules so they go directly into production')

        # flag to manually demote specific rules to staging during deploy
        subparser.add_argument('--stage-rules',
                               action=MutuallyExclusiveStagingAction,
                               default=set(),
                               help='Stage the rules provided in a space-separated list',
                               nargs='+')

        # flag to manually bypass rule staging for specific rules during deploy
        subparser.add_argument('--unstage-rules',
                               action=MutuallyExclusiveStagingAction,
                               default=set(),
                               help='Unstage the rules provided in a space-separated list',
                               nargs='+')

        # flag to manually bypass approvals for StreamAlert deploys
        subparser.add_argument(
            '--auto-approve',
            action='store_true',
            help='Automatically approve Terraform applies.',
        )

        add_default_lambda_args(subparser)

    @classmethod
    def handler(cls, options, config):
        """CLI handler for deploying new versions of Lambda functions

        Args:
            options (argparse.Namespace): Parsed argparse namespace from the CLI
            config (CLIConfig): Loaded StreamAlert config

        Returns:
            bool: False if errors occurred, True otherwise
        """
        # Make sure the Terraform code is up to date
        if not terraform_generate_handler(config=config):
            return False

        if not deploy(config, options.functions, options.clusters, options.auto_approve):
            return False

        # Update the rule table now if the rules engine is being deployed
        if 'rule' in set(options.functions):
            _update_rule_table(options, config)

        return True


def deploy(config, functions, clusters=None, auto_approve=False):
    """Deploy the functions

    Args:
        functions (set): Set of functions being deployed
        config (CLIConfig): Loaded StreamAlert config
        clusters (set=None): Optional clusters to target for this deploy

    Returns:
        bool: False if errors occurred, True otherwise
    """
    LOGGER.info('Deploying: %s', ', '.join(sorted(functions)))

    # Terraform apply only to the module which contains our lambda functions
    clusters = clusters or config.clusters()

    deploy_targets = _lambda_terraform_targets(config, functions, clusters)

    LOGGER.debug('Applying terraform targets: %s', ', '.join(sorted(deploy_targets)))

    # Terraform applies the new package and publishes a new version
    return terraform_runner(config, targets=deploy_targets, auto_approve=auto_approve)


def _update_rule_table(options, config):
    """Update the rule table with any staging information

    Args:
        options (argparse.Namespace): Various options from the CLI needed for actions
        config (CLIConfig): The loaded StreamAlert config
    """
    # If rule staging is disabled, do not update the rules table
    if not config['global']['infrastructure']['rule_staging'].get('enabled', False):
        return

    # Get the rule import paths to load
    rule_import_paths = config['global']['general']['rule_locations']

    table_name = f"{config['global']['account']['prefix']}_streamalert_rules"
    table = rule_table.RuleTable(table_name, *rule_import_paths)
    table.update(options.skip_rule_staging)

    if options.stage_rules or options.unstage_rules:
        rules = {rule_name: False
                 for rule_name in options.unstage_rules
                 } | {rule_name: True
                      for rule_name in options.stage_rules}

        for rule, stage in rules.items():
            table.toggle_staged_state(rule, stage)


def _lambda_terraform_targets(config, functions, clusters):
    """Return any terraform targets for the function(s) being deployed

    NOTE: This is very hacky and should go away. A complete refactor of how we peform
        terraform generation would help with this, but this hack will do for now.

    Args:
        config (CLIConfig): The loaded StreamAlert config
        functions (list): Functions to target during deploy
        clusters (list): Clusters to target during deploy

    Returns:
        set: Terraform module paths to target during this deployment
    """

    target_mapping = {
        'alert': {
            'targets': {
                'module.alert_processor_iam',
                'module.alert_processor_lambda',
            },
            'enabled': True
        },
        'alert_merger': {
            'targets': {
                'module.alert_merger_iam',
                'module.alert_merger_lambda',
            },
            'enabled': True
        },
        'athena': {
            'targets': {
                'module.athena_partitioner_iam',
                'module.athena_partitioner_lambda',
            },
            'enabled': True
        },
        'rule': {
            'targets': {
                'module.rules_engine_iam',
                'module.rules_engine_lambda',
            },
            'enabled': True
        },
        'classifier': {
            'targets': {
                f'module.classifier_{cluster}_{suffix}'
                for suffix in {'lambda', 'iam'} for cluster in clusters
            },
            'enabled': bool(clusters)
        },
        'apps': {
            'targets': {
                f"module.app_{app_info['app_name']}_{cluster}_{suffix}"
                for suffix in {'lambda', 'iam'}
                for cluster in clusters for app_info in config['clusters'][cluster]['modules'].get(
                    'streamalert_apps', {}).values() if 'app_name' in app_info
            },
            'enabled':
            any(info['modules'].get('streamalert_apps') for info in config['clusters'].values())
        },
        'rule_promo': {
            'targets': {
                'module.rule_promotion_iam',
                'module.rule_promotion_lambda',
            },
            'enabled': config['lambda'].get('rule_promotion_config', {}).get('enabled', False)
        },
        'scheduled_queries': {
            'targets': {
                'module.scheduled_queries',
            },
            'enabled': config['scheduled_queries'].get('enabled', False),
        },
        'threat_intel_downloader': {
            'targets': {
                'module.threat_intel_downloader',
                'module.threat_intel_downloader_iam',
            },
            'enabled': config['lambda'].get('threat_intel_downloader_config', False),
        }
    }  # required function  # required function  # required function  # required function

    targets = set()
    for function in functions:
        if not target_mapping[function]['enabled']:
            LOGGER.warning('Function is not enabled and will be ignored: %s', function)
            continue

        targets.update(target_mapping[function]['targets'])

    return targets

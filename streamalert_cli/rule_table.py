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
from streamalert.shared.rule_table import RuleTable
from streamalert_cli.utils import (CLICommand, UniqueSortedListAction,
                                   generate_subparser)


class RuleStagingCommand(CLICommand):
    description = 'Perform actions related to rule staging'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the rule staging subparser: manage.py rule-staging [subcommand] [options]"""
        rule_staging_subparsers = subparser.add_subparsers(dest='rule-staging subcommand',
                                                           required=True)

        cls._setup_rule_staging_enable_subparser(rule_staging_subparsers)
        cls._setup_rule_staging_status_subparser(rule_staging_subparsers)
        cls._setup_rule_staging_stage_subparser(rule_staging_subparsers)
        cls._setup_rule_staging_unstage_subparser(rule_staging_subparsers)

    @staticmethod
    def _setup_rule_staging_enable_subparser(subparsers):
        """Add the rule staging enable subparser: manage.py rule-staging enable"""
        rule_staging_enable_parser = generate_subparser(
            subparsers,
            'enable',
            description='Enable or disable the rule staging feature',
            subcommand=True)

        toggle_group = rule_staging_enable_parser.add_mutually_exclusive_group(required=True)
        toggle_group.add_argument('-t',
                                  '--true',
                                  dest='enable',
                                  help='Enable the rule staging feature',
                                  action='store_true')
        toggle_group.add_argument('-f',
                                  '--false',
                                  dest='enable',
                                  help='Disable the rule staging feature',
                                  action='store_false')

    @staticmethod
    def _setup_rule_staging_status_subparser(subparsers):
        """Add the rule staging status subparser: manage.py rule-staging status"""
        rule_staging_status_parser = generate_subparser(
            subparsers,
            'status',
            description='List all rules within the rule database and their staging status',
            subcommand=True)

        rule_staging_status_parser.add_argument(
            '-v',
            '--verbose',
            action='store_true',
            help='Output additional information for rules in the database')

    @classmethod
    def _setup_rule_staging_stage_subparser(cls, subparsers):
        """Add the rule staging stage subparser: manage.py rule-staging stage"""
        rule_staging_stage_parser = generate_subparser(subparsers,
                                                       'stage',
                                                       description='Stage the provided rules',
                                                       subcommand=True)

        cls._add_default_rule_staging_args(rule_staging_stage_parser)

    @classmethod
    def _setup_rule_staging_unstage_subparser(cls, subparsers):
        """Add the rule staging unstage subparser: manage.py rule-staging unstage"""
        rule_staging_unstage_parser = generate_subparser(subparsers,
                                                         'unstage',
                                                         description='Unstage the provided rules',
                                                         subcommand=True)

        cls._add_default_rule_staging_args(rule_staging_unstage_parser)

    @staticmethod
    def _add_default_rule_staging_args(subparser):
        """Add the default arguments to the rule staging parsers"""
        subparser.add_argument(
            'rules',
            action=UniqueSortedListAction,
            default=[],
            help='One or more rule to perform this action against, seperated by spaces',
            nargs='+')

    @classmethod
    def handler(cls, options, config):
        """Handle operations related to the rule table (listing, updating, etc)

        Args:
            options (argparse.Namespace): Various options needed by subcommand
                handlers
            config (CLIConfig): Loaded configuration from 'conf/' directory

        Returns:
            bool: False if errors occurred, True otherwise
        """
        if options.subcommand == 'enable':
            config.toggle_rule_staging(options.enable)

        table_name = f"{config['global']['account']['prefix']}_streamalert_rules"
        if options.subcommand == 'status':
            #print(RuleTable.print_status(table_name, verbose=options.verbose))
            #print(RuleTable(table_name).__str__(options.verbose))
            print(RuleTable(table_name),verbose = options.verbose)
        if options.subcommand in {'stage', 'unstage'}:
            stage = (options.subcommand == 'stage')
            table = RuleTable(table_name)
            for rule in options.rules:
                table.toggle_staged_state(rule, stage)

        return True

#! /usr/bin/env python
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

---------------------------------------------------------------------------

This script builds StreamAlert AWS infrastructure, is responsible for
deploying to AWS Lambda, and publishing production versions.

To run terraform by hand, change to the terraform directory and run:

terraform <cmd>
"""
import os
import textwrap
from abc import abstractmethod
from argparse import (Action, ArgumentTypeError, RawDescriptionHelpFormatter,
                      _AppendAction)

from streamalert.apps.config import AWS_RATE_HELPER, AWS_RATE_RE

CLUSTERS = [
    os.path.splitext(cluster)[0] for _, _, files in os.walk('./conf/clusters') for cluster in files
]


def function_map():
    """Provide a map of CLI function name to their expected actual function suffix

    Returns:
        dict: Mapping of CLI function name to expected actual function suffix
    """
    # This is purposely not a constant because it is expected to be modifiable
    return {
        'alert': 'alert_processor',
        'alert_merger': 'alert_merger',
        'apps': None,  # needs special handling
        'athena': 'athena_partitioner',
        'classifier': None,  # needs special handling
        'rule': 'rules_engine',
        'rule_promo': 'rule_promotion',
        'scheduled_queries': 'scheduled_queries_runner',
        'threat_intel_downloader': 'threat_intel_downloader',
    }


class CLICommand:
    """
    An abstract class that encapsulates the logic of a single manage.py CLI command.
    """
    description = NotImplemented

    @classmethod
    @abstractmethod
    def setup_subparser(cls, subparser):
        """
        Code that sets up an ArgParser subparser.
        """

    @classmethod
    @abstractmethod
    def handler(cls, options, config):
        """
        Code that is executed when the command is run.
        """


class UniqueSortedListAction(Action):
    """Subclass of argparse.Action to avoid multiple of the same choice from a list"""
    def __call__(self, parser, namespace, values, option_string=None):
        unique_items = set(values)
        setattr(namespace, self.dest, sorted(unique_items))  # We want this to be consistent


class UniqueSortedFileListAction(Action):
    """Subclass of argparse.Action to avoid multiple of the same choice from a list of files"""
    def __call__(self, parser, namespace, values, option_string=None):
        unique_items = {value.name for value in values}
        setattr(namespace, self.dest, sorted(unique_items))  # We want this to be consistent


class UniqueSortedFileListAppendAction(_AppendAction):
    """Subclass of argparse._AppendAction to avoid multiple of the same choice from a list of files

    This is meant to augment the 'append' argparse action
    """
    def __call__(self, parser, namespace, value, option_string=None):
        unique_items = set(getattr(namespace, self.dest, set()))
        unique_items.add(value.name)
        setattr(namespace, self.dest, sorted(unique_items))  # We want this to be consistent


class MutuallyExclusiveStagingAction(Action):
    """Subclass of argparse.Action to avoid staging and unstaging the same rules"""
    def __call__(self, parser, namespace, values, option_string=None):
        unique_items = set(values)
        error = ('The following rules cannot be within both the \'--stage-rules\' argument '
                 'and the \'--unstage-rules\' argument: {}')
        if namespace.unstage_rules:
            if offending_rules := unique_items.intersection(namespace.unstage_rules):
                raise parser.error(error.format(', '.join(list(offending_rules))))
        if namespace.stage_rules:
            if offending_rules := unique_items.intersection(namespace.stage_rules):
                raise parser.error(error.format(', '.join(list(offending_rules))))
        setattr(namespace, self.dest, unique_items)


class DirectoryType:
    """Factory for ensuring a directory exists"""
    def __call__(self, value):
        if os.path.isdir(value):
            return value

        raise ArgumentTypeError(f"\'{value}\' is not a directory")


def add_timeout_arg(parser):
    """Add the timeout argument to a parser"""
    def _validator(val):
        """Validate acceptable inputs for the timeout of the function"""
        error = 'Value for \'timeout\' must be an integer between 10 and 900'
        try:
            timeout = int(val)
        except ValueError as exc:
            raise parser.error(error) from exc

        if not 10 <= timeout <= 900:
            raise parser.error(error)

        return timeout

    parser.add_argument('-t',
                        '--timeout',
                        required=True,
                        help=('The AWS Lambda function timeout value, in seconds. '
                              'This should be an integer between 10 and 900.'),
                        type=_validator)


def add_memory_arg(parser):
    """Add the memory argument to a parser"""
    def _validator(val):
        """Validate the memory value to ensure it is between 128 and 3008 and a multiple of 64"""
        error = (
            'Value for \'memory\' must be an integer between 128 and 3008, and be a multiple of 64')
        try:
            memory = int(val)
        except ValueError as exc:
            raise parser.error(error) from exc

        if not 128 <= memory <= 3008:
            raise parser.error(error)

        if memory % 64 != 0:
            raise parser.error(error)

        return memory

    parser.add_argument(
        '-m',
        '--memory',
        required=True,
        help=('The AWS Lambda function max memory value, in megabytes. '
              'This should be an integer between 128 and 3008, and be a multiple of 64.'),
        type=_validator)


def add_schedule_expression_arg(parser):
    """Add the schedule expression argument to a parser"""
    def _validator(val):
        """Validate the schedule expression rate value for acceptable input"""
        rate_match = AWS_RATE_RE.match(val)
        if rate_match:
            return val

        if val.startswith('rate('):
            err = ('Invalid rate expression \'{}\'. For help see {}'.format(
                val, f'{AWS_RATE_HELPER}#RateExpressions'))
            raise parser.error(err)

        raise parser.error('Invalid expression \'{}\'. For help '
                           'see {}'.format(val, AWS_RATE_HELPER))

    schedule_help = (
        'The interval, defined using a \'rate\' expression, at which this function should '
        'execute. Examples of acceptable input are: \'rate(1 hour)\', \'rate(2 days)\', and '
        '\'rate(20 minutes)\'. For more information, see: {}').format(AWS_RATE_HELPER)

    parser.add_argument('-s',
                        '--schedule-expression',
                        required=True,
                        help=schedule_help,
                        type=_validator)


def add_clusters_arg(parser, required=False):
    """Add ability to select 0 or more clusters to act against"""
    kwargs = {
        'choices': CLUSTERS,
        'help': 'One or more clusters to target' if required else 'One or more clusters to target. '
        'If omitted, this action will be performed against all clusters.',
        'nargs': '+',
        'action': UniqueSortedListAction,
        'required': required
    }

    if not required:
        kwargs['default'] = CLUSTERS

    parser.add_argument('-c', '--clusters', **kwargs)


def set_parser_epilog(parser, epilog):
    """Set the epilog on the given parser. This will typically be an 'Example' block"""
    parser.epilog = textwrap.dedent(epilog) if epilog else None


def generate_subparser(parser, name, description=None, subcommand=False, **kwargs):
    """Helper function to return a subparser with the given options"""
    subparser = parser.add_parser(name,
                                  description=description,
                                  formatter_class=RawDescriptionHelpFormatter,
                                  **kwargs)

    if subcommand:
        subparser.set_defaults(subcommand=name)
    else:
        subparser.set_defaults(command=name)

    return subparser


def add_default_lambda_args(lambda_parser):
    """Add the default arguments to the deploy and rollback parsers"""
    functions = sorted(function_map())
    # optionally allow for the name of 1+ functions being deployed/rolled back
    lambda_parser.add_argument(
        '-f',
        '--functions',
        choices=functions,
        default=functions,
        metavar='FUNCTIONS',
        help=
        (f"One or more of the following functions to perform this action against: {', '.join(functions)}. "
         f"If omitted, this action will be performed against all functions."),
        nargs='+',
        action=UniqueSortedListAction)

    # Add the option to specify cluster(s)
    add_clusters_arg(lambda_parser)

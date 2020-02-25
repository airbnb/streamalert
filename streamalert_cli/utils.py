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
from abc import abstractmethod
from argparse import Action, RawDescriptionHelpFormatter
import os
import textwrap
from streamalert.apps.config import AWS_RATE_RE, AWS_RATE_HELPER

CLUSTERS = [
    os.path.splitext(cluster)[0] for _, _, files in os.walk('./conf/clusters')
    for cluster in files
]


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


class MutuallyExclusiveStagingAction(Action):
    """Subclass of argparse.Action to avoid staging and unstaging the same rules"""

    def __call__(self, parser, namespace, values, option_string=None):
        unique_items = set(values)
        error = (
            'The following rules cannot be within both the \'--stage-rules\' argument '
            'and the \'--unstage-rules\' argument: {}'
        )
        if namespace.unstage_rules:
            offending_rules = unique_items.intersection(namespace.unstage_rules)
            if offending_rules:
                raise parser.error(error.format(', '.join(list(offending_rules))))
        if namespace.stage_rules:
            offending_rules = unique_items.intersection(namespace.stage_rules)
            if offending_rules:
                raise parser.error(error.format(', '.join(list(offending_rules))))
        setattr(namespace, self.dest, unique_items)


def add_timeout_arg(parser):
    """Add the timeout argument to a parser"""
    def _validator(val):
        """Validate acceptable inputs for the timeout of the function"""
        error = 'Value for \'timeout\' must be an integer between 10 and 900'
        try:
            timeout = int(val)
        except ValueError:
            raise parser.error(error)

        if not 10 <= timeout <= 900:
            raise parser.error(error)

        return timeout

    parser.add_argument(
        '-t',
        '--timeout',
        required=True,
        help=(
            'The AWS Lambda function timeout value, in seconds. '
            'This should be an integer between 10 and 900.'
        ),
        type=_validator
    )


def add_memory_arg(parser):
    """Add the memory argument to a parser"""
    def _validator(val):
        """Validate the memory value to ensure it is between 128 and 3008 and a multiple of 64"""
        error = (
            'Value for \'memory\' must be an integer between 128 and 3008, and be a multiple of 64'
        )
        try:
            memory = int(val)
        except ValueError:
            raise parser.error(error)

        if not 128 <= memory <= 3008:
            raise parser.error(error)

        if memory % 64 != 0:
            raise parser.error(error)

        return memory

    parser.add_argument(
        '-m',
        '--memory',
        required=True,
        help=(
            'The AWS Lambda function max memory value, in megabytes. '
            'This should be an integer between 128 and 3008, and be a multiple of 64.'
        ),
        type=_validator
    )


def add_schedule_expression_arg(parser):
    """Add the schedule expression argument to a parser"""
    def _validator(val):
        """Validate the schedule expression rate value for acceptable input"""
        rate_match = AWS_RATE_RE.match(val)
        if rate_match:
            return val

        if val.startswith('rate('):
            err = ('Invalid rate expression \'{}\'. For help see {}'
                   .format(val, '{}#RateExpressions'.format(AWS_RATE_HELPER)))
            raise parser.error(err)

        raise parser.error('Invalid expression \'{}\'. For help '
                           'see {}'.format(val, AWS_RATE_HELPER))

    schedule_help = (
        'The interval, defined using a \'rate\' expression, at which this function should '
        'execute. Examples of acceptable input are: \'rate(1 hour)\', \'rate(2 days)\', and '
        '\'rate(20 minutes)\'. For more information, see: {}'
    ).format(AWS_RATE_HELPER)

    parser.add_argument(
        '-s',
        '--schedule-expression',
        required=True,
        help=schedule_help,
        type=_validator
    )


def add_clusters_arg(parser, required=False):
    """Add ability to select 0 or more clusters to act against"""
    kwargs = {
        'choices': CLUSTERS,
        'help': (
            'One or more clusters to target. '
            'If omitted, this action will be performed against all clusters.'
        ) if not required else 'One or more clusters to target',
        'nargs': '+',
        'action': UniqueSortedListAction,
        'required': required
    }

    if not required:
        kwargs['default'] = CLUSTERS

    parser.add_argument(
        '-c',
        '--clusters',
        **kwargs
    )


def set_parser_epilog(parser, epilog):
    """Set the epilog on the given parser. This will typically be an 'Example' block"""
    parser.epilog = textwrap.dedent(epilog) if epilog else None


def generate_subparser(parser, name, description=None, subcommand=False, **kwargs):
    """Helper function to return a subparser with the given options"""
    subparser = parser.add_parser(
        name,
        description=description,
        formatter_class=RawDescriptionHelpFormatter,
        **kwargs
    )

    if subcommand:
        subparser.set_defaults(subcommand=name)
    else:
        subparser.set_defaults(command=name)

    return subparser


def add_default_lambda_args(lambda_parser):
    """Add the default arguments to the deploy and rollback parsers"""

    functions = sorted([
        'alert', 'alert_merger', 'apps', 'athena', 'classifier',
        'rule', 'rule_promo', 'scheduled_queries', 'threat_intel_downloader'
    ])
    # require the name of the function being deployed/rolled back
    lambda_parser.add_argument(
        '-f', '--function',
        choices=functions + ['all'],
        metavar='FUNCTION',
        help=(
            'One or more of the following functions to perform this action against: {}. '
            'Use \'all\' to act against all functions.'
        ).format(', '.join(functions)),
        nargs='+',
        action=UniqueSortedListAction,
        required=True
    )

    # Add the option to specify cluster(s)
    add_clusters_arg(lambda_parser)

#! /usr/bin/env python
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

---------------------------------------------------------------------------

This script builds StreamAlert AWS infrastructure, is responsible for
deploying to AWS Lambda, and publishing production versions.

To run terraform by hand, change to the terraform directory and run:

terraform <cmd>
"""
# pylint: disable=too-many-lines
from abc import abstractmethod
from argparse import Action, ArgumentParser, RawDescriptionHelpFormatter
import os
import string
import sys
import textwrap

from stream_alert import __version__ as version
from stream_alert.alert_processor.outputs.output_base import StreamAlertOutput
from stream_alert.apps import StreamAlertApp
from stream_alert.apps.config import AWS_RATE_RE, AWS_RATE_HELPER
from stream_alert.shared import CLUSTERED_FUNCTIONS, metrics
from stream_alert_cli.test import DEFAULT_TEST_FILES_DIRECTORY
from stream_alert_cli.runner import cli_runner

CLUSTERS = [
    os.path.splitext(cluster)[0] for _, _, files in os.walk('../conf/clusters')
    for cluster in files
]


class CliCommand(object):
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


class UniqueSetAction(Action):
    """Subclass of argparse.Action to avoid multiple of the same choice from a list"""

    def __call__(self, parser, namespace, values, option_string=None):
        unique_items = set(values)
        setattr(namespace, self.dest, unique_items)


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
        'action': UniqueSetAction,
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


def generate_subparser(parser, name, description=None, subcommand=False):
    """Helper function to return a subparser with the given options"""
    subparser = parser.add_parser(
        name,
        description=description,
        formatter_class=RawDescriptionHelpFormatter
    )

    if subcommand:
        subparser.set_defaults(subcommand=name)
    else:
        subparser.set_defaults(command=name)

    return subparser













def _setup_test_subparser(subparser):
    """Add the test subparser: manage.py test"""
    test_subparsers = subparser.add_subparsers(dest="test subcommand", required=True)

    _setup_test_classifier_subparser(test_subparsers)
    _setup_test_rules_subparser(test_subparsers)
    _setup_test_live_subparser(test_subparsers)


def _setup_test_classifier_subparser(subparsers):
    """Add the test validation subparser: manage.py test classifier [options]"""
    test_validate_parser = generate_subparser(
        subparsers,
        'classifier',
        description='Validate defined log schemas using integration test files',
        subcommand=True
    )

    _add_default_test_args(test_validate_parser)


def _setup_test_rules_subparser(subparsers):
    """Add the test rules subparser: manage.py test rules [options]"""
    test_rules_parser = generate_subparser(
        subparsers,
        'rules',
        description='Test rules using integration test files',
        subcommand=True
    )

    # Flag to run additional stats during testing
    test_rules_parser.add_argument(
        '-s',
        '--stats',
        action='store_true',
        help='Enable outputing of statistical information on rules that run'
    )

    # Validate the provided repitition value
    def _validate_repitition(val):
        """Make sure the input is between 1 and 1000"""
        err = ('Invalid repitition value [{}]. Must be an integer between 1 '
               'and 1000').format(val)
        try:
            count = int(val)
        except TypeError:
            raise test_rules_parser.error(err)

        if not 1 <= count <= 1000:
            raise test_rules_parser.error(err)

        return count

    # flag to run these tests a given number of times
    test_rules_parser.add_argument(
        '-n',
        '--repeat',
        default=1,
        type=_validate_repitition,
        help='Number of times to repeat the tests, to be used as a form performance testing'
    )

    _add_default_test_args(test_rules_parser)


def _setup_test_live_subparser(subparsers):
    """Add the test live subparser: manage.py test live [options]"""
    test_live_parser = generate_subparser(
        subparsers,
        'live',
        description='Run end-to-end tests that will attempt to send alerts to each rule\'s outputs',
        subcommand=True
    )

    _add_default_test_args(test_live_parser)


def _add_default_test_args(test_parser):
    """Add the default arguments to the test parsers"""
    test_filter_group = test_parser.add_mutually_exclusive_group(required=False)

    # add the optional ability to test against a rule/set of rules
    test_filter_group.add_argument(
        '-f',
        '--test-files',
        dest='files',
        metavar='FILENAMES',
        nargs='+',
        help='One or more file to test, separated by spaces',
        action=UniqueSetAction,
        default=set()
    )

    # add the optional ability to test against a rule/set of rules
    test_filter_group.add_argument(
        '-r',
        '--test-rules',
        dest='rules',
        nargs='+',
        help='One or more rule to test, separated by spaces',
        action=UniqueSetAction,
        default=set()
    )

    # add the optional ability to change the test files directory
    test_parser.add_argument(
        '-d',
        '--files-dir',
        help='Path to directory containing test files',
        default=DEFAULT_TEST_FILES_DIRECTORY
    )

    # Add the optional ability to log verbosely or use quite logging for tests
    verbose_group = test_parser.add_mutually_exclusive_group(required=False)

    verbose_group.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Output additional information during testing'
    )

    verbose_group.add_argument(
        '-q',
        '--quiet',
        action='store_true',
        help='Suppress output for passing tests, only logging if there is a failure'
    )


def add_default_lambda_args(lambda_parser):
    """Add the default arguments to the deploy and rollback parsers"""

    functions = sorted([
        'alert', 'alert_merger', 'apps', 'athena', 'classifier',
        'rule', 'rule_promo', 'threat_intel_downloader'
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
        action=UniqueSetAction,
        required=True
    )

    # Add the option to specify cluster(s)
    add_clusters_arg(lambda_parser)




def _setup_kinesis_subparser(subparser):
    """Add kinesis subparser: manage.py kinesis [options]"""
    _set_parser_epilog(
        subparser,
        epilog=(
            '''\
            Example:

                manage.py kinesis disable-events --clusters corp prod
            '''
        )
    )

    actions = ['disable-events', 'enable-events']
    subparser.add_argument(
        'action',
        metavar='ACTION',
        choices=actions,
        help='One of the following actions to be performed: {}'.format(', '.join(actions))
    )

    # Add the option to specify cluster(s)
    add_clusters_arg(subparser)

    subparser.add_argument(
        '-s',
        '--skip-terraform',
        action='store_true',
        help='Only update the config options and do not run Terraform'
    )









def _setup_threat_intel_subparser(subparser):
    """Add threat intel subparser: manage.py threat-intel [action]"""
    _set_parser_epilog(
        subparser,
        epilog=(
            '''\
            Examples:

                manage.py threat-intel \\
                  enable \\
                  --dynamodb-table my_ioc_table
            '''
        )
    )

    actions = ['disable', 'enable']
    subparser.add_argument(
        'action',
        metavar='ACTION',
        choices=actions,
        help='One of the following actions to be performed: {}'.format(', '.join(actions))
    )

    subparser.add_argument(
        '--dynamodb-table',
        dest='dynamodb_table_name',
        help='DynamoDB table name where IOC information is stored'
    )


def _setup_threat_intel_configure_subparser(subparsers):
    """Add threat intel downloader configure subparser

    manage.py threat-intel-downloader configure [options]
    """
    ti_downloader_configure_parser = _generate_subparser(
        subparsers,
        'configure',
        description='Enable, disable, or configure the threat intel downloader function',
        subcommand=True
    )

    # Enable/Disable toggle group
    toggle_group = ti_downloader_configure_parser.add_mutually_exclusive_group(required=False)

    toggle_group.add_argument(
        '-e',
        '--enable',
        dest='enable_threat_intel_downloader',
        help='Enable the threat intel downloader function',
        action='store_true'
    )

    toggle_group.add_argument(
        '-d',
        '--disable',
        dest='enable_threat_intel_downloader',
        help='Disable the threat intel downloader function',
        action='store_false'
    )

    # Function schedule expression (rate) arg
    add_schedule_expression_arg(ti_downloader_configure_parser)

    # Function timeout arg
    add_timeout_arg(ti_downloader_configure_parser)

    # Function memory arg
    add_memory_arg(ti_downloader_configure_parser)

    ti_downloader_configure_parser.add_argument(
        '-r',
        '--table-rcu',
        help='Read capacity units to use for the DynamoDB table',
        type=int,
        default=10
    )

    ti_downloader_configure_parser.add_argument(
        '-w',
        '--table-wcu',
        help='Write capacity units to use for the DynamoDB table',
        type=int,
        default=10
    )

    ti_downloader_configure_parser.add_argument(
        '-k',
        '--ioc-keys',
        help='One or more IOC keys to store in DynamoDB table',
        nargs='+',
        action=UniqueSetAction,
        default=['expiration_ts', 'itype', 'source', 'type', 'value']
    )

    ti_downloader_configure_parser.add_argument(
        '-f',
        '--ioc-filters',
        help='One or more filters to apply when retrieving IOCs from Threat Feed',
        nargs='+',
        action=UniqueSetAction,
        default=['crowdstrike', '@airbnb.com']
    )

    ti_downloader_configure_parser.add_argument(
        '-i',
        '--ioc-types',
        help='One or more IOC type defined by the Threat Feed. IOC types can vary by feed',
        nargs='+',
        action=UniqueSetAction,
        default=['domain', 'ip', 'md5']
    )

    ti_downloader_configure_parser.add_argument(
        '-x',
        '--excluded-sub-types',
        help='IOC subtypes to be excluded',
        action=UniqueSetAction,
        default=['bot_ip', 'brute_ip', 'scan_ip', 'spam_ip', 'tor_ip']
    )

    ti_downloader_configure_parser.add_argument(
        '-a',
        '--autoscale',
        help='Enable auto scaling for the threat intel DynamoDB table',
        default=False,
        action='store_true'
    )

    ti_downloader_configure_parser.add_argument(
        '--max-read-capacity',
        help='Maximum read capacity to use when auto scaling is enabled',
        type=int,
        default=5
    )

    ti_downloader_configure_parser.add_argument(
        '--min-read-capacity',
        help='Minimum read capacity to use when auto scaling is enabled',
        type=int,
        default=5
    )

    ti_downloader_configure_parser.add_argument(
        '-u',
        '--target-utilization',
        help=(
            'Target percentage of consumed provisioned throughput at a point in time '
            'to use for auto-scaling the read capacity units'
        ),
        type=int,
        default=70
    )


def _setup_threat_intel_auth_subparser(subparsers):
    """Add threat intel downloader update-auth subparser

    manage.py threat-intel-downloader update-auth
    """
    _generate_subparser(
        subparsers,
        'update-auth',
        description='Enable, disable, or configure the threat intel downloader function',
        subcommand=True
    )


def _setup_threat_intel_downloader_subparser(subparser):
    """Add threat intel downloader subparser: manage.py threat-intel-downloader [subcommand]"""
    ti_subparsers = subparser.add_subparsers(dest="threat-intel-downloader subcommand",
                                             required=True)

    _setup_threat_intel_configure_subparser(ti_subparsers)
    _setup_threat_intel_auth_subparser(ti_subparsers)



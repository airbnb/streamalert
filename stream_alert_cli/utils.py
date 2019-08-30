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


def _setup_output_subparser(subparser):
    """Add the output subparser: manage.py output SERVICE"""
    outputs = sorted(StreamAlertOutput.get_all_outputs().keys())

    # Output parser arguments
    subparser.add_argument(
        'service',
        choices=outputs,
        metavar='SERVICE',
        help='Create a new StreamAlert output for one of the available services: {}'.format(
            ', '.join(outputs)
        )
    )










def _setup_custom_metrics_subparser(subparser):
    """Add the metrics subparser: manage.py custom-metrics [options]"""
    _set_parser_epilog(
        subparser,
        epilog=(
            '''\
            Example:

                manage.py custom-metrics --enable --functions rule
            '''
        )
    )

    available_metrics = metrics.MetricLogger.get_available_metrics()
    available_functions = [func for func, value in available_metrics.items() if value]

    # allow the user to select 1 or more functions to enable metrics for
    subparser.add_argument(
        '-f',
        '--functions',
        choices=available_functions,
        metavar='FUNCTION',
        help='One or more of the following functions for which to enable metrics: {}'.format(
            ', '.join(available_functions)
        ),
        nargs='+',
        required=True
    )

    # get the metric toggle value
    toggle_group = subparser.add_mutually_exclusive_group(required=True)

    toggle_group.add_argument(
        '-e',
        '--enable',
        dest='enable_custom_metrics',
        help='Enable custom CloudWatch metrics',
        action='store_true'
    )

    toggle_group.add_argument(
        '-d',
        '--disable',
        dest='enable_custom_metrics',
        help='Disable custom CloudWatch metrics',
        action='store_false'
    )

    # Add the option to specify cluster(s)
    add_clusters_arg(subparser)


def _add_default_metric_alarms_args(alarm_parser, clustered=False):
    """Add the default arguments to the metric alarm parsers"""
    # Name for this alarm
    def _alarm_name_validator(val):
        if not 1 <= len(val) <= 255:
            raise alarm_parser.error('alarm name length must be between 1 and 255')
        return val

    alarm_parser.add_argument(
        'alarm_name',
        help='Name for the alarm. Each alarm name must be unique within the AWS account.',
        type=_alarm_name_validator
    )

    # get the available metrics to be used
    available_metrics = metrics.MetricLogger.get_available_metrics()

    if clustered:
        available_functions = [
            func for func, value in available_metrics.items()
            if func in CLUSTERED_FUNCTIONS and value
        ]
    else:
        available_functions = [func for func, value in available_metrics.items() if value]

    all_metrics = [metric for func in available_functions for metric in available_metrics[func]]

    # add metrics for user to pick from. Will be mapped to 'metric_name' in terraform
    alarm_parser.add_argument(
        '-m',
        '--metric',
        choices=all_metrics,
        dest='metric_name',
        metavar='METRIC_NAME',
        help=(
            'One of the following predefined metrics to assign this alarm to for a '
            'given function: {}'
        ).format(', '.join(sorted(all_metrics))),
        required=True
    )

    # Get the function to apply this alarm to
    alarm_parser.add_argument(
        '-f',
        '--function',
        metavar='FUNCTION',
        choices=available_functions,
        help=(
            'One of the following Lambda functions to which to apply this alarm: {}'
        ).format(', '.join(sorted(available_functions))),
        required=True
    )

    operators = sorted([
        'GreaterThanOrEqualToThreshold', 'GreaterThanThreshold', 'LessThanThreshold',
        'LessThanOrEqualToThreshold'
    ])

    # get the comparison type for this metric
    alarm_parser.add_argument(
        '-co',
        '--comparison-operator',
        metavar='OPERATOR',
        choices=operators,
        help=(
            'One of the following comparison operator to use for this metric: {}'
        ).format(', '.join(operators)),
        required=True
    )

    # get the evaluation period for this alarm
    def _alarm_eval_periods_validator(val):
        error = 'evaluation periods must be an integer greater than 0'
        try:
            period = int(val)
        except ValueError:
            raise alarm_parser.error(error)

        if period <= 0:
            raise alarm_parser.error(error)
        return period

    alarm_parser.add_argument(
        '-e',
        '--evaluation-periods',
        help=(
            'The number of periods over which data is compared to the specified threshold. '
            'The minimum value for this is 1. See the \'Other Constraints\' section below for '
            'more information'
        ),
        required=True,
        type=_alarm_eval_periods_validator
    )

    # get the period for this alarm
    def _alarm_period_validator(val):
        error = 'period must be an integer in multiples of 60'
        try:
            period = int(val)
        except ValueError:
            raise alarm_parser.error(error)

        if period <= 0 or period % 60 != 0:
            raise alarm_parser.error(error)

        return period

    alarm_parser.add_argument(
        '-p',
        '--period',
        help=(
            'The period, in seconds, over which the specified statistic is applied. '
            'Valid values are any multiple of 60. See the \'Other Constraints\' section below for '
            'more information'
        ),
        required=True,
        type=_alarm_period_validator
    )

    # get the threshold for this alarm
    alarm_parser.add_argument(
        '-t',
        '--threshold',
        help=(
            'The value against which the specified statistic is compared. '
            'This value should be a double/float.'
        ),
        required=True,
        type=float
    )

    # all other optional flags
    # get the optional alarm description
    def _alarm_description_validator(val):
        if len(val) > 1024:
            raise alarm_parser.error('alarm description length must be less than 1024')
        return val

    alarm_parser.add_argument(
        '-d',
        '--alarm-description',
        help='A description for the alarm',
        type=_alarm_description_validator,
        default=''
    )

    statistics = sorted(['SampleCount', 'Average', 'Sum', 'Minimum', 'Maximum'])

    alarm_parser.add_argument(
        '-s',
        '--statistic',
        metavar='STATISTIC',
        choices=statistics,
        help=(
            'One of the following statistics to use for the metric associated with the alarm: {}'
        ).format(', '.join(statistics)),
        default='Sum'
    )


def _setup_cluster_metric_alarm_subparser(subparser):
    """Add the create-cluster-alarm subparser: manage.py create-cluster-alarm [options]"""
    _set_parser_epilog(
        subparser,
        epilog=(
            '''\
            Other Constraints:

                The product of the value for period multiplied by the value for evaluation
                periods cannot exceed 86,400. 86,400 is the number of seconds in one day and
                an alarm's total current evaluation period can be no longer than one day.

            Example:

                manage.py create-cluster-alarm FailedParsesAlarm \\
                  --metric FailedParses \\
                  --comparison-operator GreaterThanOrEqualToThreshold \\
                  --evaluation-periods 1 \\
                  --period 300 \\
                  --threshold 1.0 \\
                  --clusters prod \\
                  --statistic Sum \\
                  --alarm-description 'Alarm for any failed parses that occur \
within a 5 minute period in the prod cluster'

            Resources:

                AWS:        https://docs.aws.amazon.com/AmazonCloudWatch/\
latest/APIReference/API_PutMetricAlarm.html
                Terraform:  https://www.terraform.io/docs/providers/aws/r/\
cloudwatch_metric_alarm.html
            '''
        )
    )

    _add_default_metric_alarms_args(subparser, clustered=True)

    # Add the option to specify cluster(s)
    add_clusters_arg(subparser, required=True)


def _setup_metric_alarm_subparser(subparser):
    """Add the create-alarm subparser: manage.py create-alarm [options]"""
    _set_parser_epilog(
        subparser,
        epilog=(
            '''\
            Other Constraints:

                The product of the value for period multiplied by the value for evaluation
                periods cannot exceed 86,400. 86,400 is the number of seconds in one day and
                an alarm's total current evaluation period can be no longer than one day.

            Example:

                manage.py create-alarm FailedParsesAlarm \\
                  --metric FailedParses \\
                  --comparison-operator GreaterThanOrEqualToThreshold \\
                  --evaluation-periods 1 \\
                  --period 300 \\
                  --threshold 1.0 \\
                  --statistic Sum \\
                  --alarm-description 'Global alarm for any failed parses that occur \
within a 5 minute period in the classifier'

            Resources:

                AWS:        https://docs.aws.amazon.com/AmazonCloudWatch/\
latest/APIReference/API_PutMetricAlarm.html
                Terraform:  https://www.terraform.io/docs/providers/aws/r/\
cloudwatch_metric_alarm.html
            '''
        )
    )

    _add_default_metric_alarms_args(subparser)


def _setup_deploy_subparser(subparser):
    """Add the deploy subparser: manage.py deploy [options]"""
    _set_parser_epilog(
        subparser,
        epilog=(
            '''\
            Example:

                manage.py deploy --function rule alert
            '''
        )
    )

    # Flag to manually bypass rule staging for new rules upon deploy
    # This only has an effect if rule staging is enabled
    subparser.add_argument(
        '--skip-rule-staging',
        action='store_true',
        help='Skip staging of new rules so they go directly into production'
    )

    # flag to manually demote specific rules to staging during deploy
    subparser.add_argument(
        '--stage-rules',
        action=MutuallyExclusiveStagingAction,
        default=set(),
        help='Stage the rules provided in a space-separated list',
        nargs='+'
    )

    # flag to manually bypass rule staging for specific rules during deploy
    subparser.add_argument(
        '--unstage-rules',
        action=MutuallyExclusiveStagingAction,
        default=set(),
        help='Unstage the rules provided in a space-separated list',
        nargs='+'
    )

    _add_default_lambda_args(subparser)


def _setup_rollback_subparser(subparser):
    """Add the rollback subparser: manage.py rollback [options]"""
    _set_parser_epilog(
        subparser,
        epilog=(
            '''\
            Example:

                manage.py rollback --function rule
            '''
        )
    )

    _add_default_lambda_args(subparser)


def _setup_test_subparser(subparser):
    """Add the test subparser: manage.py test"""
    test_subparsers = subparser.add_subparsers(dest="test subcommand", required=True)

    _setup_test_classifier_subparser(test_subparsers)
    _setup_test_rules_subparser(test_subparsers)
    _setup_test_live_subparser(test_subparsers)


def _setup_test_classifier_subparser(subparsers):
    """Add the test validation subparser: manage.py test classifier [options]"""
    test_validate_parser = _generate_subparser(
        subparsers,
        'classifier',
        description='Validate defined log schemas using integration test files',
        subcommand=True
    )

    _add_default_test_args(test_validate_parser)


def _setup_test_rules_subparser(subparsers):
    """Add the test rules subparser: manage.py test rules [options]"""
    test_rules_parser = _generate_subparser(
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
    test_live_parser = _generate_subparser(
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


def _add_default_lambda_args(lambda_parser):
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


def _setup_init_subparser(subparser):
    """Add init subparser: manage.py init [options]"""
    subparser.add_argument(
        '-b',
        '--backend',
        action='store_true',
        help=(
            'Initialize the Terraform backend (S3). '
            'Useful for refreshing a pre-existing deployment'
        )
    )


def _add_default_tf_args(tf_parser):
    """Add the default terraform parser options"""
    tf_parser.add_argument(
        '-t',
        '--target',
        metavar='TARGET',
        help=(
            'One or more Terraform module name to target. Use `list-targets` for a list '
            'of available targets'
        ),
        action=UniqueSetAction,
        default=set(),
        nargs='+'
    )

    # Add the option to specify cluster(s)
    add_clusters_arg(tf_parser)


def _setup_build_subparser(subparser):
    """Add build subparser: manage.py build [options]"""
    _set_parser_epilog(
        subparser,
        epilog=(
            '''\
            Example:

                manage.py build --target alert_processor_lambda
            '''
        )
    )

    _add_default_tf_args(subparser)


def _setup_destroy_subparser(subparser):
    """Add destroy subparser: manage.py destroy [options]"""
    _set_parser_epilog(
        subparser,
        epilog=(
            '''\
            Example:

                manage.py destroy --target aws_s3_bucket.streamalerts
            '''
        )
    )

    _add_default_tf_args(subparser)


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


def _setup_rule_staging_subparser(subparser):
    """Add the rule staging subparser: manage.py rule-staging [subcommand] [options]"""
    rule_staging_subparsers = subparser.add_subparsers(dest="rule-staging subcommand",
                                                       required=True)

    _setup_rule_staging_enable_subparser(rule_staging_subparsers)
    _setup_rule_staging_status_subparser(rule_staging_subparsers)
    _setup_rule_staging_stage_subparser(rule_staging_subparsers)
    _setup_rule_staging_unstage_subparser(rule_staging_subparsers)

def _setup_rule_staging_enable_subparser(subparsers):
    """Add the rule staging enable subparser: manage.py rule-staging enable"""
    rule_staging_enable_parser = _generate_subparser(
        subparsers,
        'enable',
        description='Enable or disable the rule staging feature',
        subcommand=True
    )

    toggle_group = rule_staging_enable_parser.add_mutually_exclusive_group(required=True)
    toggle_group.add_argument(
        '-t',
        '--true',
        dest='enable',
        help='Enable the rule staging feature',
        action='store_true'
    )
    toggle_group.add_argument(
        '-f',
        '--false',
        dest='enable',
        help='Disable the rule staging feature',
        action='store_false'
    )


def _setup_rule_staging_status_subparser(subparsers):
    """Add the rule staging status subparser: manage.py rule-staging status"""
    rule_staging_status_parser = _generate_subparser(
        subparsers,
        'status',
        description='List all rules within the rule database and their staging status',
        subcommand=True
    )

    rule_staging_status_parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Output additional information for rules in the database'
    )


def _setup_rule_staging_stage_subparser(subparsers):
    """Add the rule staging stage subparser: manage.py rule-staging stage"""
    rule_staging_stage_parser = _generate_subparser(
        subparsers,
        'stage',
        description='Stage the provided rules',
        subcommand=True
    )

    _add_default_rule_staging_args(rule_staging_stage_parser)


def _setup_rule_staging_unstage_subparser(subparsers):
    """Add the rule staging unstage subparser: manage.py rule-staging unstage"""
    rule_staging_unstage_parser = _generate_subparser(
        subparsers,
        'unstage',
        description='Unstage the provided rules',
        subcommand=True
    )

    _add_default_rule_staging_args(rule_staging_unstage_parser)


def _add_default_rule_staging_args(subparser):
    """Add the default arguments to the rule staging parsers"""
    subparser.add_argument(
        'rules',
        action=UniqueSetAction,
        default=set(),
        help='One or more rule to perform this action against, seperated by spaces',
        nargs='+'
    )

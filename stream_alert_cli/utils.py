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
import os
import textwrap
from abc import abstractmethod
from argparse import RawDescriptionHelpFormatter, Action

from stream_alert.apps.config import AWS_RATE_RE, AWS_RATE_HELPER
from stream_alert.shared import metrics, CLUSTERED_FUNCTIONS


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


def set_parser_epilog(parser, epilog):
    """Set the epilog on the given parser. This will typically be an 'Example' block"""
    parser.epilog = textwrap.dedent(epilog) if epilog else None


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


def add_default_tf_args(tf_parser):
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


CLUSTERS = [
    os.path.splitext(cluster)[0] for _, _, files in os.walk('../conf/clusters')
    for cluster in files
]


def add_default_metric_alarms_args(alarm_parser, clustered=False):
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
            func for func, value in available_metrics.iteritems()
            if func in CLUSTERED_FUNCTIONS and value
        ]
    else:
        available_functions = [func for func, value in available_metrics.iteritems() if value]

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

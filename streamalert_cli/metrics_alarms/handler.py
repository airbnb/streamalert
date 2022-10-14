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
from streamalert.shared import CLUSTERED_FUNCTIONS, metrics
from streamalert.shared.logger import get_logger
from streamalert_cli.utils import (CLICommand, add_clusters_arg,
                                   set_parser_epilog)

LOGGER = get_logger(__name__)


class CreateMetricAlarmCommand(CLICommand):
    description = 'Add a global CloudWatch alarm for predefined metrics for a given function'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the create-alarm subparser: manage.py create-alarm [options]"""
        set_parser_epilog(subparser,
                          epilog=('''\
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
                '''))

        _add_default_metric_alarms_args(subparser)

    @classmethod
    def handler(cls, options, config):
        return _create_alarm_handler(options, config)


class CreateClusterMetricAlarmCommand(CLICommand):
    description = 'Add a CloudWatch alarm for predefined metrics for a given cluster/function'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the create-cluster-alarm subparser: manage.py create-cluster-alarm [options]"""
        set_parser_epilog(subparser,
                          epilog=('''\
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
                '''))

        _add_default_metric_alarms_args(subparser, clustered=True)

        # Add the option to specify cluster(s)
        add_clusters_arg(subparser, required=True)

    @classmethod
    def handler(cls, options, config):
        return _create_alarm_handler(options, config)


class CustomMetricsCommand(CLICommand):
    description = 'Enable or disable custom metrics for the lambda functions'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the metrics subparser: manage.py custom-metrics [options]"""
        set_parser_epilog(subparser,
                          epilog=('''\
                Example:

                    manage.py custom-metrics --enable --functions rule
                '''))

        available_metrics = metrics.MetricLogger.get_available_metrics()
        available_functions = [func for func, value in available_metrics.items() if value]

        # allow the user to select 1 or more functions to enable metrics for
        subparser.add_argument(
            '-f',
            '--functions',
            choices=available_functions,
            metavar='FUNCTION',
            help=
            f"One or more of the following functions for which to enable metrics: {', '.join(available_functions)}",
            nargs='+',
            required=True)

        # get the metric toggle value
        toggle_group = subparser.add_mutually_exclusive_group(required=True)

        toggle_group.add_argument('-e',
                                  '--enable',
                                  dest='enable_custom_metrics',
                                  help='Enable custom CloudWatch metrics',
                                  action='store_true')

        toggle_group.add_argument('-d',
                                  '--disable',
                                  dest='enable_custom_metrics',
                                  help='Disable custom CloudWatch metrics',
                                  action='store_false')

        # Add the option to specify cluster(s)
        add_clusters_arg(subparser)

    @classmethod
    def handler(cls, options, config):
        """
        Enable or disable logging CloudWatch metrics

        Args:
            options (argparse.Namespace): Contains boolean necessary for toggling metrics

        Returns:
            bool: False if errors occurred, True otherwise
        """
        config.toggle_metrics(*options.functions,
                              enabled=options.enable_custom_metrics,
                              clusters=options.clusters)

        return True


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
        type=_alarm_name_validator)

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
        help=('One of the following predefined metrics to assign this alarm to for a '
              'given function: {}').format(', '.join(sorted(all_metrics))),
        required=True)

    # Get the function to apply this alarm to
    alarm_parser.add_argument(
        '-f',
        '--function',
        metavar='FUNCTION',
        choices=available_functions,
        help=('One of the following Lambda functions to which to apply this alarm: {}').format(
            ', '.join(sorted(available_functions))),
        required=True)

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
        help=('One of the following comparison operator to use for this metric: {}').format(
            ', '.join(operators)),
        required=True)

    # get the evaluation period for this alarm
    def _alarm_eval_periods_validator(val):
        error = 'evaluation periods must be an integer greater than 0'
        try:
            period = int(val)
        except ValueError as err:
            raise alarm_parser.error(error) from err

        if period <= 0:
            raise alarm_parser.error(error)
        return period

    alarm_parser.add_argument(
        '-e',
        '--evaluation-periods',
        help=('The number of periods over which data is compared to the specified threshold. '
              'The minimum value for this is 1. See the \'Other Constraints\' section below for '
              'more information'),
        required=True,
        type=_alarm_eval_periods_validator)

    # get the period for this alarm
    def _alarm_period_validator(val):
        error = 'period must be an integer in multiples of 60'
        try:
            period = int(val)
        except ValueError as err:
            raise alarm_parser.error(error) from err

        if period <= 0 or period % 60 != 0:
            raise alarm_parser.error(error)

        return period

    alarm_parser.add_argument(
        '-p',
        '--period',
        help=(
            'The period, in seconds, over which the specified statistic is applied. '
            'Valid values are any multiple of 60. See the \'Other Constraints\' section below for '
            'more information'),
        required=True,
        type=_alarm_period_validator)

    # get the threshold for this alarm
    alarm_parser.add_argument('-t',
                              '--threshold',
                              help=('The value against which the specified statistic is compared. '
                                    'This value should be a double/float.'),
                              required=True,
                              type=float)

    # all other optional flags
    # get the optional alarm description
    def _alarm_description_validator(val):
        if len(val) > 1024:
            raise alarm_parser.error('alarm description length must be less than 1024')
        return val

    alarm_parser.add_argument('-d',
                              '--alarm-description',
                              help='A description for the alarm',
                              type=_alarm_description_validator,
                              default='')

    statistics = sorted(['SampleCount', 'Average', 'Sum', 'Minimum', 'Maximum'])

    alarm_parser.add_argument(
        '-s',
        '--statistic',
        metavar='STATISTIC',
        choices=statistics,
        help=('One of the following statistics to use for the metric associated with the alarm: {}'
              ).format(', '.join(statistics)),
        default='Sum')


def _create_alarm_handler(options, config):
    """Create a new CloudWatch alarm for the given metric

    Args:
        options (argparse.Namespace): Contains all of the necessary info for configuring
            a CloudWatch alarm

    Returns:
        bool: False if errors occurred, True otherwise
    """
    # Perform safety check for max total evaluation period. This logic cannot
    # be performed by argparse so must be performed now.
    seconds_in_day = 86400
    if options.period * options.evaluation_periods > seconds_in_day:
        LOGGER.error('The product of the value for period multiplied by the '
                     'value for evaluation periods cannot exceed 86,400. 86,400 '
                     'is the number of seconds in one day and an alarm\'s total '
                     'current evaluation period can be no longer than one day.')
        return False

    return config.add_metric_alarm(vars(options))

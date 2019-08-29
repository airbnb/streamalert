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
from stream_alert.shared import metrics
from stream_alert.shared.logger import get_logger
from stream_alert_cli.utils import set_parser_epilog, add_default_metric_alarms_args, CliCommand, \
    add_clusters_arg

LOGGER = get_logger(__name__)


class MetricAlarmCommand(CliCommand):

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the create-alarm subparser: manage.py create-alarm [options]"""
        set_parser_epilog(
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

        add_default_metric_alarms_args(subparser)

    @classmethod
    def handler(cls, options, config):
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


class CustomMetricsCommand(CliCommand):

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the metrics subparser: manage.py custom-metrics [options]"""
        set_parser_epilog(
            subparser,
            epilog=(
                '''\
                Example:

                    manage.py custom-metrics --enable --functions rule
                '''
            )
        )

        available_metrics = metrics.MetricLogger.get_available_metrics()
        available_functions = [func for func, value in available_metrics.iteritems() if value]

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

    @classmethod
    def handler(cls, options, config):
        """Enable or disable logging CloudWatch metrics

        Args:
            options (argparse.Namespace): Contains boolean necessary for toggling metrics

        Returns:
            bool: False if errors occurred, True otherwise
        """
        config.toggle_metrics(
            *options.functions,
            enabled=options.enable_custom_metrics,
            clusters=options.clusters
        )

        return True


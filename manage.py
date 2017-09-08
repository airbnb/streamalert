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

terraform <cmd> -var-file=../terraform.tfvars -var-file=../variables.json
"""
from argparse import Action, ArgumentParser, RawTextHelpFormatter, SUPPRESS as ARGPARSE_SUPPRESS
import os

from stream_alert.shared import metrics
from stream_alert_cli import __version__ as version
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.runner import cli_runner


class UniqueSetAction(Action):
    """Subclass of argparse.Action to avoid multiple of the same choice from a list"""
    def __call__(self, parser, namespace, values, option_string=None):
        unique_items = set(values)
        setattr(namespace, self.dest, unique_items)


class NormalizeFunctionAction(UniqueSetAction):
    """Subclass of argparse.Action -> UniqueSetAction that will return a unique set of
    normalized lambda function names.
    """
    def __call__(self, parser, namespace, values, option_string=None):
        super(NormalizeFunctionAction, self).__call__(parser, namespace, values, option_string)
        values = getattr(namespace, self.dest)
        normalized_map = {'rule': metrics.RULE_PROCESSOR_NAME,
                          'alert': metrics.ALERT_PROCESSOR_NAME,
                          'athena': metrics.ATHENA_PARTITION_REFRESH_NAME}

        for func, normalize_func in normalized_map.iteritems():
            if func in values:
                values.remove(func)
                values.add(normalize_func)

        setattr(namespace, self.dest, values)


def _add_output_subparser(subparsers):
    """Add the output subparser: manage.py output [subcommand] [options]"""
    output_usage = 'manage.py output [subcommand] [options]'
    output_description = ("""
StreamAlertCLI v{}
Define new StreamAlert outputs to send alerts to

Available Subcommands:

    manage.py output new [options]    Create a new StreamAlert output

Examples:

    manage.py output new --service <service_name>
    manage.py output new --service aws-s3
    manage.py output new --service pagerduty
    manage.py output new --service slack

""".format(version))
    output_parser = subparsers.add_parser(
        'output',
        description=output_description,
        usage=output_usage,
        formatter_class=RawTextHelpFormatter,
        help='Define a new output to send alerts to'
    )

    # Set the name of this parser to 'output'
    output_parser.set_defaults(command='output')

    # Output parser arguments
    # The CLI library handles all configuration logic
    output_parser.add_argument(
        'subcommand',
        choices=['new'],
        help=ARGPARSE_SUPPRESS
    )
    # Output service options
    output_parser.add_argument(
        '--service',
        choices=['aws-lambda', 'aws-s3', 'pagerduty', 'phantom', 'slack'],
        required=True,
        help=ARGPARSE_SUPPRESS
    )
    output_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )


def _add_live_test_subparser(subparsers):
    """Add the live-test subparser: manage.py live-test [options]"""
    live_test_usage = 'manage.py live-test [options]'
    live_test_description = ("""
StreamAlertCLI v{}
Run end-to-end tests that will attempt to send alerts

Available Options:

    --cluster               The cluster name to use for live testing
    --rules                 Name of rules to test, separated by spaces
    --debug                 Enable Debug logger output

Examples:

    manage.py live-test --cluster prod
    manage.py live-test --rules

""".format(version))
    live_test_parser = subparsers.add_parser(
        'live-test',
        description=live_test_description,
        usage=live_test_usage,
        formatter_class=RawTextHelpFormatter,
        help=ARGPARSE_SUPPRESS
    )

    # set the name of this parser to 'live-test'
    live_test_parser.set_defaults(command='live-test')

    # get cluster choices from available files
    clusters = [os.path.splitext(cluster)[0] for _, _, files
                in os.walk('conf/clusters') for cluster in files]

    # add clusters for user to pick from
    live_test_parser.add_argument(
        '-c', '--cluster',
        choices=clusters,
        help=ARGPARSE_SUPPRESS,
        required=True
    )

    # add the optional ability to test against a rule/set of rules
    live_test_parser.add_argument(
        '-r', '--rules',
        nargs='+',
        help=ARGPARSE_SUPPRESS
    )

    # allow verbose output for the CLI with the --debug option
    live_test_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )


def _add_validate_schema_subparser(subparsers):
    """Add the validate-schemas subparser: manage.py validate-schemas [options]"""
    schema_validation_usage = 'manage.py validate-schemas [options]'
    schema_validation_description = ("""
StreamAlertCLI v{}
Run validation of schemas in logs.json using configured integration test files. Validation
does not actually run the rules engine on test events.

Available Options:

    --test-files         Name(s) of test files to validate, separated by spaces (not full path)
                           These files should be located within 'tests/integration/rules/' and each
                           should be named according to the rule they are meant to test. The
                           contents should be json, in the form of `{{"records": [ <records as maps> ]}}`.
                           See the sample test files in 'tests/integration/rules/' for an example.
                           The '--test-files' flag will accept the full file name, with extension,
                           or the base file name, without extension (ie: test_file_name.json or
                           test_file_name are both acceptable arguments)
    --debug              Enable Debug logger output

Examples:

    manage.py validate-schemas --test-files <test_file_name_01.json> <test_file_name_02.json>

""".format(version))
    schema_validation_parser = subparsers.add_parser(
        'validate-schemas',
        description=schema_validation_description,
        usage=schema_validation_usage,
        formatter_class=RawTextHelpFormatter,
        help=ARGPARSE_SUPPRESS
    )

    # Set the name of this parser to 'validate-schemas'
    schema_validation_parser.set_defaults(command='validate-schemas')

    # add the optional ability to test against specific files
    schema_validation_parser.add_argument(
        '-f', '--test-files',
        nargs='+',
        help=ARGPARSE_SUPPRESS
    )

    # allow verbose output for the CLI with the --debug option
    schema_validation_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )


def _add_metrics_subparser(subparsers):
    """Add the metrics subparser: manage.py metrics [options]"""
    metrics_usage = 'manage.py metrics [options]'

    # get cluster choices from available files
    clusters = [os.path.splitext(cluster)[0] for _, _, files
                in os.walk('conf/clusters') for cluster in files]

    cluster_choices_block = ('\n').join('{:>28}{}'.format('', cluster) for cluster in clusters)

    metrics_description = ("""
StreamAlertCLI v{}
Enable or disable metrics for all lambda functions. This toggles the creation of metric filters.

Available Options:

    -e/--enable         Enable CloudWatch metrics through logging and metric filters
    -d/--disable        Disable CloudWatch metrics through logging and metric filters
    -f/--functions      Space delimited list of functions to enable metrics for
                          Choices are:
                            rule
                            alert (not implemented)
                            athena (not implemented)
    --debug             Enable Debug logger output

Optional Arguemnts:

    -c/--clusters       Space delimited list of clusters to enable metrics for. If
                          omitted, this will enable metrics for all clusters. Choices are:
{}
Examples:

    manage.py metrics --enable --functions rule

""".format(version, cluster_choices_block))

    metrics_parser = subparsers.add_parser(
        'metrics',
        description=metrics_description,
        usage=metrics_usage,
        formatter_class=RawTextHelpFormatter,
        help=ARGPARSE_SUPPRESS
    )

    # Set the name of this parser to 'metrics'
    metrics_parser.set_defaults(command='metrics')

    # allow the user to select 1 or more functions to enable metrics for
    metrics_parser.add_argument(
        '-f', '--functions',
        choices=['rule', 'alert', 'athena'],
        help=ARGPARSE_SUPPRESS,
        nargs='+',
        action=NormalizeFunctionAction,
        required=True
    )

    # get the metric toggle value
    toggle_group = metrics_parser.add_mutually_exclusive_group(required=True)

    toggle_group.add_argument(
        '-e', '--enable',
        dest='enable_metrics',
        action='store_true'
    )

    toggle_group.add_argument(
        '-d', '--disable',
        dest='enable_metrics',
        action='store_false'
    )

    # allow the user to select 0 or more clusters to enable metrics for
    metrics_parser.add_argument(
        '-c', '--clusters',
        choices=clusters,
        help=ARGPARSE_SUPPRESS,
        nargs='+',
        action=UniqueSetAction,
        default=clusters
    )

    # allow verbose output for the CLI with the --debug option
    metrics_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )


def _add_metric_alarm_subparser(subparsers):
    """Add the create-alarm subparser: manage.py create-alarm [options]"""
    metric_alarm_usage = 'manage.py create-alarm [options]'

    # get the available metrics to be used
    available_metrics = metrics.MetricLogger.get_available_metrics()
    all_metrics = [metric for func in available_metrics for metric in available_metrics[func]]

    metric_choices_block = ('\n').join('{:>35}{}'.format('', metric) for metric in all_metrics)

    # get cluster choices from available files
    clusters = [os.path.splitext(cluster)[0] for _, _, files
                in os.walk('conf/clusters') for cluster in files]

    cluster_choices_block = ('\n').join('{:>37}{}'.format('', cluster) for cluster in clusters)

    metric_alarm_description = ("""
StreamAlertCLI v{}
Add a CloudWatch alarm for predefined metrics. These are save in the config and
Terraform is used to create the alarms.

Required Arguments:

    -m/--metric                  The predefined metric to assign this alarm to. Choices are:
{}
    -mt/--metric-target          The target of this metric alarm, meaning either the cluster metric
                                   or the aggrea metric. Choices are:
                                     cluster
                                     aggregate
                                     all
    -co/--comparison-operator    Comparison operator to use for this metric. Choices are:
                                   GreaterThanOrEqualToThreshold
                                   GreaterThanThreshold
                                   LessThanThreshold
                                   LessThanOrEqualToThreshold
    -an/--alarm-name             The name for the alarm. This name must be unique within the AWS
                                   account
    -ep/--evaluation-periods     The number of periods over which data is compared to the specified
                                   threshold. The minimum value for this is 1. Also see the 'Other
                                   Constraints' section below
    -p/--period                  The period, in seconds, over which the specified statistic is
                                   applied. Valid values are any multiple of 60. Also see the
                                   'Other Constraints' section below
    -t/--threshold               The value against which the specified statistic is compared. This
                                   value should be a double.

Optional Arguments:

    -ad/--alarm-description      The description for the alarm
    -c/--clusters                Space delimited list of clusters to apply this metric to. This is
                                   ignored if the --metric-target of 'aggregate' is used.
                                   Choices are:
{}
    -s/--statistic               The statistic for the metric associated with the alarm.
                                   Choices are:
                                     SampleCount
                                     Average
                                     Sum
                                     Minimum
                                     Maximum
    --debug                      Enable Debug logger output

Other Constraints:

    The product of the value for period multiplied by the value for evaluation periods cannot
    exceed 86,400. 86,400 is the number of seconds in one day and an alarm's total current
    evaluation period can be no longer than one day.

Examples:

    manage.py create-alarm \\
      --metric FailedParses \\
      --metric-target cluster \\
      --comparison-operator GreaterThanOrEqualToThreshold \\
      --alarm-name FailedParsesAlarm \\
      --evaluation-periods 1 \\
      --period 300 \\
      --threshold 1.0 \\
      --alarm-description 'Alarm for any failed parses that occur within a 5 minute period in the prod cluster' \\
      --clusters prod \\
      --statistic Sum

Resources:

    AWS:        https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html
    Terraform:  https://www.terraform.io/docs/providers/aws/r/cloudwatch_metric_alarm.html

""".format(version, metric_choices_block, cluster_choices_block))

    metric_alarm_parser = subparsers.add_parser(
        'create-alarm',
        description=metric_alarm_description,
        usage=metric_alarm_usage,
        formatter_class=RawTextHelpFormatter,
        help=ARGPARSE_SUPPRESS
    )

    # Set the name of this parser to 'validate-schemas'
    metric_alarm_parser.set_defaults(command='create-alarm')

    # add all the required parameters
    # add metrics for user to pick from. Will be mapped to 'metric_name' in terraform
    metric_alarm_parser.add_argument(
        '-m', '--metric',
        choices=all_metrics,
        dest='metric_name',
        help=ARGPARSE_SUPPRESS,
        required=True
    )

    # check to see what the user wants to apply this metric to (cluster, aggregate, or both)
    metric_alarm_parser.add_argument(
        '-mt', '--metric-target',
        choices=['cluster', 'aggregate', 'all'],
        help=ARGPARSE_SUPPRESS,
        required=True
    )

    # get the comparison type for this metric
    metric_alarm_parser.add_argument(
        '-co', '--comparison-operator',
        choices=['GreaterThanOrEqualToThreshold', 'GreaterThanThreshold',
                 'LessThanThreshold', 'LessThanOrEqualToThreshold'],
        help=ARGPARSE_SUPPRESS,
        required=True
    )

    # get the name of the alarm
    def _alarm_name_validator(val):
        if not 1 <= len(val) <= 255:
            raise metric_alarm_parser.error('alarm name length must be between 1 and 255')
        return val

    metric_alarm_parser.add_argument(
        '-an', '--alarm-name',
        help=ARGPARSE_SUPPRESS,
        required=True,
        type=_alarm_name_validator
    )

    # get the evaluation period for this alarm
    def _alarm_eval_periods_validator(val):
        error = 'evaluation periods must be an integer greater than 0'
        try:
            period = int(val)
        except ValueError:
            raise metric_alarm_parser.error(error)

        if period <= 0:
            raise metric_alarm_parser.error(error)
        return period

    metric_alarm_parser.add_argument(
        '-ep', '--evaluation-periods',
        help=ARGPARSE_SUPPRESS,
        required=True,
        type=_alarm_eval_periods_validator
    )

    # get the period for this alarm
    def _alarm_period_validator(val):
        error = 'period must be an integer in multiples of 60'
        try:
            period = int(val)
        except ValueError:
            raise metric_alarm_parser.error(error)

        if period <= 0 or period % 60 != 0:
            raise metric_alarm_parser.error(error)

        return period

    metric_alarm_parser.add_argument(
        '-p', '--period',
        help=ARGPARSE_SUPPRESS,
        required=True,
        type=_alarm_period_validator
    )

    # get the threshold for this alarm
    metric_alarm_parser.add_argument(
        '-t', '--threshold',
        help=ARGPARSE_SUPPRESS,
        required=True,
        type=float
    )

    # all other optional flags
    # get the optional alarm description
    def _alarm_description_validator(val):
        if len(val) > 1024:
            raise metric_alarm_parser.error('alarm description length must be less than 1024')
        return val

    metric_alarm_parser.add_argument(
        '-ad', '--alarm-description',
        help=ARGPARSE_SUPPRESS,
        type=_alarm_description_validator
    )

    # allow the user to select 0 or more clusters to apply this alarm to
    metric_alarm_parser.add_argument(
        '-c', '--clusters',
        choices=clusters,
        help=ARGPARSE_SUPPRESS,
        nargs='+',
        action=UniqueSetAction,
        default=[]
    )

    ### Commenting out the below until we can support 'extended-statistic' metrics
    ### alongside 'statistic' metrics. Currently only 'statistic' are supported
    # # get the extended statistic or statistic value
    # statistic_group = metric_alarm_parser.add_mutually_exclusive_group()
    # def _extended_stat_validator(val):
    #     if not re.search(r'p(\d{1,2}(\.\d{0,2})?|100)$', val):
    #         raise metric_alarm_parser.error('extended statistic values must start with \'p\' '
    #                                         'and be followed by a percentage value (ie: p0.0, '
    #                                         'p10, p55.5, p100)')
    #     return val
    #
    # statistic_group.add_argument(
    #     '-es', '--extended-statistic',
    #     help=ARGPARSE_SUPPRESS,
    #     type=_extended_stat_validator
    # )
    #
    # statistic_group.add_argument(
    #     '-s', '--statistic',
    #     choices=['SampleCount', 'Average', 'Sum', 'Minimum', 'Maximum'],
    #     help=ARGPARSE_SUPPRESS
    # )

    metric_alarm_parser.add_argument(
        '-s', '--statistic',
        choices=['SampleCount', 'Average', 'Sum', 'Minimum', 'Maximum'],
        help=ARGPARSE_SUPPRESS
    )

    # allow verbose output for the CLI with the --debug option
    metric_alarm_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )



def _add_lambda_subparser(subparsers):
    """Add the Lambda subparser: manage.py lambda [subcommand] [options]"""
    lambda_usage = 'manage.py lambda [subcommand] [options]'
    lambda_description = ("""
StreamAlertCLI v{}
Deploy, Rollback, and Test StreamAlert Lambda functions

Available Subcommands:

    manage.py lambda deploy [options]         Deploy Lambda functions
    manage.py lambda rollback [options]       Rollback Lambda functions
    manage.py lambda test [options]           Run rule tests

Available Options:

    --processor                                         The name of the Lambda function to manage.
                                                        Valid options include: rule, alert, or all.
    --debug                                             Enable Debug logger output.
    --rules                                             List of rules to test, separated by spaces.

Examples:

    manage.py lambda deploy --processor all
    manage.py lambda rollback --processor all
    manage.py lambda test --processor rule --rules lateral_movement root_logins

""".format(version))
    lambda_parser = subparsers.add_parser(
        'lambda',
        usage=lambda_usage,
        description=lambda_description,
        help=ARGPARSE_SUPPRESS,
        formatter_class=RawTextHelpFormatter
    )

    # Set the name of this parser to 'lambda'
    lambda_parser.set_defaults(command='lambda')

    # Add subcommand options for the lambda sub-parser
    lambda_parser.add_argument(
        'subcommand',
        choices=['deploy', 'rollback', 'test'],
        help=ARGPARSE_SUPPRESS
    )

    # require the name of the processor being deployed/rolled back/tested
    lambda_parser.add_argument(
        '--processor',
        choices=['alert', 'all', 'athena', 'rule'],
        help=ARGPARSE_SUPPRESS,
        action='append',
        required=True
    )

    # allow verbose output for the CLI with the --debug option
    lambda_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )

    # add the optional ability to test against a rule/set of rules
    lambda_parser.add_argument(
        '-r', '--rules',
        nargs='+',
        help=ARGPARSE_SUPPRESS
    )


def _add_terraform_subparser(subparsers):
    """Add Terraform subparser: manage.py terraform [subcommand] [options]"""
    terraform_usage = 'manage.py terraform [subcommand] [options]'
    terraform_description = ("""
StreamAlertCLI v{}
Plan and Apply StreamAlert Infrastructure with Terraform

Available Subcommands:

    manage.py terraform init                   Initialize StreamAlert infrastructure
    manage.py terraform init-backend           Initialize the Terraform backend
    manage.py terraform build [options]        Run Terraform on all StreamAlert modules
    manage.py terraform clean                  Remove Terraform files (only use this when destroying all infrastructure)
    manage.py terraform destroy [options]      Destroy StreamAlert infrastructure
    manage.py terraform generate               Generate Terraform files from JSON cluster files
    manage.py terraform status                 Show cluster health, and other currently configured infrastructure information

Available Options:

    --target                                   The Terraform module name to apply.
                                               Valid options: stream_alert, kinesis, kinesis_events,
                                               cloudtrail, monitoring, and s3_events.
Examples:

    manage.py terraform init
    manage.py terraform init-backend
    manage.py terraform generate

    manage.py terraform build
    manage.py terraform build --target kinesis
    manage.py terraform build --target stream_alert

    manage.py terraform destroy
    manage.py terraform destroy -target cloudtrail

""".format(version))
    tf_parser = subparsers.add_parser(
        'terraform',
        usage=terraform_usage,
        description=terraform_description,
        help=ARGPARSE_SUPPRESS,
        formatter_class=RawTextHelpFormatter
    )

    # set the name of this parser to 'terraform'
    tf_parser.set_defaults(command='terraform')

    # add subcommand options for the terraform sub-parser
    tf_parser.add_argument(
        'subcommand',
        choices=['build',
                 'clean',
                 'destroy',
                 'init',
                 'init-backend',
                 'generate',
                 'status'],
        help=ARGPARSE_SUPPRESS
    )

    tf_parser.add_argument(
        '--target',
        choices=['athena',
                 'cloudwatch_monitoring',
                 'cloudtrail',
                 'flow_logs',
                 'kinesis',
                 'kinesis_events',
                 'stream_alert',
                 's3_events'],
        help=ARGPARSE_SUPPRESS,
        nargs='+'
    )

    tf_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )


def _add_configure_subparser(subparsers):
    """Add configure subparser: manage.py configure [config_key] [config_value]"""
    configure_usage = 'manage.py configure [config_key] [config_value]'
    configure_description = ("""
StreamAlertCLI v{}
Configure StreamAlert options

Available Keys:

    prefix                     Resource prefix
    aws_account_id             AWS account number

Examples:

    manage.py configure prefix my-organization

""".format(version))
    configure_parser = subparsers.add_parser(
        'configure',
        usage=configure_usage,
        description=configure_description,
        help=ARGPARSE_SUPPRESS,
        formatter_class=RawTextHelpFormatter
    )

    configure_parser.set_defaults(command='configure')

    configure_parser.add_argument(
        'config_key',
        choices=['prefix',
                 'aws_account_id'],
        help=ARGPARSE_SUPPRESS
    )

    configure_parser.add_argument(
        'config_value',
        help=ARGPARSE_SUPPRESS
    )

    configure_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )


def _add_athena_subparser(subparsers):
    """Add athena subparser: manage.py athena [subcommand]"""
    athena_usage = 'manage.py athena [subcommand]'
    athena_description = ("""
StreamAlertCLI v{}
Athena StreamAlert options

Available Subcommands:

    manage.py athena init                 Create the Athena base config
    manage.py athena enable               Enable Athena Partition Refresh Lambda function
    manage.py athena create-db            Initialize the Athena Database (streamalert)
    manage.py athena create-table         Create an Athena table

Examples:

    manage.py athena create-db
    manage.py athena create-table --type alerts --bucket s3.bucket.name

""".format(version))
    athena_parser = subparsers.add_parser(
        'athena',
        usage=athena_usage,
        description=athena_description,
        help=ARGPARSE_SUPPRESS,
        formatter_class=RawTextHelpFormatter
    )

    athena_parser.set_defaults(command='athena')

    athena_parser.add_argument(
        'subcommand',
        choices=['init', 'enable', 'create-db', 'create-table'],
        help=ARGPARSE_SUPPRESS
    )

    # TODO(jacknagz): Create a second choice for data tables, and accept a log name argument.
    athena_parser.add_argument(
        '--type',
        choices=['alerts'],
        help=ARGPARSE_SUPPRESS
    )

    athena_parser.add_argument(
        '--bucket',
        help=ARGPARSE_SUPPRESS
    )

    athena_parser.add_argument(
        '--refresh_type',
        choices=['add_hive_partition', 'repair_hive_table'],
        help=ARGPARSE_SUPPRESS
    )

    athena_parser.add_argument(
        '--debug',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )


def build_parser():
    """Build the argument parser."""
    description = ("""
StreamAlertCLI v{}
Build, Deploy, Configure, and Test StreamAlert Infrastructure

Available Commands:

    manage.py terraform        Manage StreamAlert infrastructure
    manage.py output           Configure new StreamAlert outputs
    manage.py lambda           Deploy, test, and rollback StreamAlert AWS Lambda functions
    manage.py live-test        Send alerts to configured outputs
    manage.py configure        Configure StreamAlert settings

For additional details on the available commands, try:

    manage.py [command] --help

""".format(version))
    usage = '%(prog)s [command] [subcommand] [options]'

    parser = ArgumentParser(
        description=description,
        prog='manage.py',
        usage=usage,
        formatter_class=RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers()
    _add_output_subparser(subparsers)
    _add_live_test_subparser(subparsers)
    _add_validate_schema_subparser(subparsers)
    _add_metrics_subparser(subparsers)
    _add_metric_alarm_subparser(subparsers)
    _add_lambda_subparser(subparsers)
    _add_terraform_subparser(subparsers)
    _add_configure_subparser(subparsers)
    _add_athena_subparser(subparsers)

    return parser


def main():
    """Entry point for the CLI."""
    parser = build_parser()
    options = parser.parse_args()
    cli_runner(options)
    LOGGER_CLI.info('Completed')


if __name__ == "__main__":
    main()

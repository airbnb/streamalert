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
# pylint: disable=too-many-lines
from argparse import Action, ArgumentParser, RawTextHelpFormatter, SUPPRESS as ARGPARSE_SUPPRESS
import os
import string


from stream_alert import __version__ as version
from stream_alert.alert_processor.outputs.output_base import StreamAlertOutput
from stream_alert.shared import metrics
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.runner import cli_runner
from app_integrations.apps.app_base import StreamAlertApp
from app_integrations.config import AWS_RATE_RE, AWS_RATE_HELPER

CLUSTERS = [
    os.path.splitext(cluster)[0] for _, _, files in os.walk('conf/clusters')
    for cluster in files
]

# TODO (ryandeivert): remove when rule staging lambda is complete
ENABLE_RULE_STAGING = False


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


class NormalizeFunctionAction(UniqueSetAction):
    """Subclass of argparse.Action -> UniqueSetAction that will return a unique set of
    normalized lambda function names.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        super(NormalizeFunctionAction, self).__call__(parser, namespace, values, option_string)
        values = getattr(namespace, self.dest)
        normalized_map = {
            'rule': metrics.RULE_PROCESSOR_NAME,
            'alert': metrics.ALERT_PROCESSOR_NAME,
            'athena': metrics.ATHENA_PARTITION_REFRESH_NAME
        }

        for func, normalize_func in normalized_map.iteritems():
            if func in values:
                values.remove(func)
                values.add(normalize_func)

        setattr(namespace, self.dest, values)


def _generate_subparser(parser, name, usage, description, subcommand=False):
    """Helper function to return a subparser with the given options"""
    subparser = parser.add_parser(
        name,
        description=description,
        formatter_class=RawTextHelpFormatter,
        help=ARGPARSE_SUPPRESS,
        usage=usage,
    )

    # allow verbose output with the --debug option
    subparser.add_argument('--debug', action='store_true', help=ARGPARSE_SUPPRESS)

    if subcommand:
        subparser.set_defaults(subcommand=name)
    else:
        subparser.set_defaults(command=name)

    return subparser


def _add_output_subparser(subparsers):
    """Add the output subparser: manage.py output [subcommand] [options]"""
    usage = 'manage.py output [subcommand] [options]'
    outputs = sorted(StreamAlertOutput.get_all_outputs().keys())
    description = """
StreamAlertCLI v{}
Define new StreamAlert outputs to send alerts to

Available Subcommands:

    manage.py output new [options]    Create a new StreamAlert output

Examples:

    manage.py output new --service aws-s3
    manage.py output new --service pagerduty
    manage.py output new --service slack

The following outputs are supported:

{}
""".format(version, '\n'.join('{:>4}{}'.format('', output) for output in outputs))

    output_parser = _generate_subparser(subparsers, 'output', usage, description)

    # Output parser arguments
    # The CLI library handles all configuration logic
    output_parser.add_argument('subcommand', choices=['new'], help=ARGPARSE_SUPPRESS)
    # Output service options
    output_parser.add_argument(
        '--service',
        choices=outputs,
        required=True,
        help=ARGPARSE_SUPPRESS)


def _add_live_test_subparser(subparsers):
    """Add the live-test subparser: manage.py live-test [options]"""
    usage = 'manage.py live-test [options]'
    description = """
StreamAlertCLI v{}
Run end-to-end tests that will attempt to send alerts

Required Arguments:

    --cluster               The cluster name to use for live testing

Optional Arguments:

    --rules                 Name of rules to test, separated by spaces
    --debug                 Enable debug logger output

Examples:

    manage.py live-test --cluster prod
    manage.py live-test --rules

""".format(version)

    live_test_parser = _generate_subparser(subparsers, 'live-test', usage, description)

    # add clusters for user to pick from
    live_test_parser.add_argument(
        '-c', '--cluster', choices=CLUSTERS, help=ARGPARSE_SUPPRESS, required=True)

    # add the optional ability to test against a rule/set of rules
    live_test_parser.add_argument(
        '-r', '--rules', nargs='+', help=ARGPARSE_SUPPRESS, action=UniqueSetAction, default=set())


def _add_validate_schema_subparser(subparsers):
    """Add the validate-schemas subparser: manage.py validate-schemas [options]"""
    usage = 'manage.py validate-schemas [options]'
    description = """
StreamAlertCLI v{}
Run validation of schemas in logs.json using configured integration test files. Validation
does not actually run the rules engine on test events.

Available Options:

    --test-files         Name(s) of test files to validate, separated by spaces (not full path).
                           These files should be located within 'tests/integration/rules/'. The
                           contents should be json, in the form of:
                             `{{"records": [ <records as maps> ]}}`.

                           See the sample test files in 'tests/integration/rules/' for an example.
                           This flag supports the full file name, with extension, or the base file
                           name, without extension (ie: test_file_name.json or test_file_name)

Optional Arguments:

    --debug              Enable debug logger output

Examples:

    manage.py validate-schemas --test-files <test_file_name_01.json> <test_file_name_02.json>

""".format(version)

    schema_validation_parser = _generate_subparser(
        subparsers, 'validate-schemas', usage, description)

    # add the optional ability to test against specific files
    schema_validation_parser.add_argument(
        '-f',
        '--test-files',
        dest='files',
        nargs='+',
        help=ARGPARSE_SUPPRESS,
        action=UniqueSetAction,
        default=set())


def _add_app_integration_subparser(subparsers):
    """Add the app integration subparser: manage.py app [subcommand] [options]"""
    usage = 'manage.py app [subcommand] [options]'
    description = """
StreamAlertCLI v{}
Create, list, or update a StreamAlert app integration function to poll logs from various services

Available Subcommands:

    manage.py app new                 Configure a new app integration for collecting logs
    manage.py app update-auth         Update the authentication information for an
                                        existing app integration

""".format(version)

    app_integration_parser = _generate_subparser(subparsers, 'app', usage, description)

    app_integration_subparsers = app_integration_parser.add_subparsers()

    _add_app_integration_list_subparser(app_integration_subparsers)
    _add_app_integration_new_subparser(
        app_integration_subparsers,
        sorted(StreamAlertApp.get_all_apps()),
        CLUSTERS
    )
    _add_app_integration_update_auth_subparser(app_integration_subparsers, CLUSTERS)


def _add_app_integration_list_subparser(subparsers):
    """Add the app list subparser: manage.py app list"""
    usage = 'manage.py app list'
    description = """
StreamAlertCLI v{}
List all configured StreamAlert app integration functions, grouped by cluseter

Command:

    manage.py app list             List all configured app functions, grouped by cluster

Optional Arguments:

    --debug                        Enable debug logger output

""".format(version)

    _generate_subparser(subparsers, 'list', usage, description, True)


def _add_app_integration_new_subparser(subparsers, types, clusters):
    """Add the app new subparser: manage.py app new [options]"""
    usage = 'manage.py app new [options]'

    types_block = '\n'.join('{:>26}{}'.format('', app_type) for app_type in types)
    cluster_choices_block = '\n'.join('{:>28}{}'.format('', cluster) for cluster in clusters)

    description = """
StreamAlertCLI v{}
Create a new StreamAlert app integration function to poll logs from various services

Command:

    manage.py app new [options]      Configure a new app for collecting logs

Required Arguments:

    --type              Type of app integration function being configured. Choices are:
{}
    --cluster           Applicable cluster this function should be configured against.
                          Choices are:
{}
    --name              Unique name to be assigned to the App. This is useful when
                          configuring multiple accounts per service.
    --timeout           The AWS Lambda function timeout value, in seconds. This should
                          be an integer between 10 and 300.
    --memory            The AWS Lambda function max memory value, in megabytes. This should
                          be an integer between 128 and 1536.
    --interval          The interval, defined using a 'rate' expression, at
                          which this app integration function should execute. Examples of
                          acceptable input are:
                            'rate(1 hour)'          # Every hour (note the singular 'hour')
                            'rate(2 days)'          # Every 2 days
                            'rate(20 minutes)'      # Every 20 minutes

                          See the link in the Resources section below for more information.

Optional Arguments:

    --debug             Enable debug logger output

Examples:

    manage.py app new \\
      --type duo_auth \\
      --cluster prod \\
      --name duo_prod_collector \\
      --interval 'rate(2 hours)' \\
      --timeout 60 \\
      --memory 256

Resources:

    AWS: {}

""".format(version, types_block, cluster_choices_block, AWS_RATE_HELPER)

    app_integration_new_parser = _generate_subparser(subparsers, 'new', usage, description, True)

    _add_default_app_integration_args(app_integration_new_parser, clusters)

    # App type options
    app_integration_new_parser.add_argument(
        '--type', choices=types, required=True, help=ARGPARSE_SUPPRESS)

    # Validate the rate at which this should run
    def _validate_scheduled_interval(val):
        """Validate acceptable inputs for the schedule expression
        These follow the format 'rate(5 minutes)'
        """
        rate_match = AWS_RATE_RE.match(val)
        if rate_match:
            return val

        if val.startswith('rate('):
            err = ('Invalid rate expression \'{}\'. For help see {}'
                   .format(val, '{}#RateExpressions'.format(AWS_RATE_HELPER)))
            raise app_integration_new_parser.error(err)

        raise app_integration_new_parser.error('Invalid expression \'{}\'. For help '
                                               'see {}'.format(val, AWS_RATE_HELPER))

    # App integration schedule expression (rate)
    app_integration_new_parser.add_argument(
        '--interval', dest='schedule_expression',
        required=True, help=ARGPARSE_SUPPRESS, type=_validate_scheduled_interval)

    # Validate the timeout value to make sure it is between 10 and 300
    def _validate_timeout(val):
        """Validate acceptable inputs for the timeout of the function"""
        error = 'The \'timeout\' value must be an integer between 10 and 300'
        try:
            timeout = int(val)
        except ValueError:
            raise app_integration_new_parser.error(error)

        if not 10 <= timeout <= 300:
            raise app_integration_new_parser.error(error)

        return timeout

    # App integration function timeout
    app_integration_new_parser.add_argument(
        '--timeout', required=True, help=ARGPARSE_SUPPRESS, type=_validate_timeout)

    # Validate the memory value to make sure it is between 128 and 1536
    def _validate_memory(val):
        """Validate acceptable inputs for the memory of the function"""
        error = 'The \'memory\' value must be an integer between 128 and 1536'
        try:
            memory = int(val)
        except ValueError:
            raise app_integration_new_parser.error(error)

        if not 128 <= memory <= 1536:
            raise app_integration_new_parser.error(error)

        return memory

    # App integration function max memory
    app_integration_new_parser.add_argument(
        '--memory', required=True, help=ARGPARSE_SUPPRESS, type=_validate_memory)

def _add_app_integration_update_auth_subparser(subparsers, clusters):
    """Add the app update-auth subparser: manage.py app update-auth [options]"""
    usage = 'manage.py app update-auth [options]'

    cluster_choices_block = '\n'.join('{:>28}{}'.format('', cluster) for cluster in clusters)

    description = """
StreamAlertCLI v{}
Update a StreamAlert app integration function's authentication information in Parameter Store

Command:

    manage.py app update-auth [options]      Update the authentication information for an
                                               existing app integration within Parameter Store

Required Arguments:

    --cluster           Applicable cluster this function should be configured against.
                          Choices are:
{}
    --name              Unique name to be assigned to the App. This is useful when
                          configuring multiple accounts per service.

Optional Arguments:

    --debug             Enable debug logger output

Examples:

    manage.py app update-auth \\
      --cluster prod \\
      --name duo_prod_collector

""".format(version, cluster_choices_block)

    app_integration_update_parser = _generate_subparser(
        subparsers, 'update-auth', usage, description, True)

    _add_default_app_integration_args(app_integration_update_parser, clusters)


def _add_default_app_integration_args(app_integration_parser, clusters):
    """Add the default arguments to the app integration parsers"""

    # App integration cluster options
    app_integration_parser.add_argument(
        '--cluster', choices=clusters, required=True, help=ARGPARSE_SUPPRESS)

    # Validate the name being used to make sure it does not contain specific characters
    def _validate_name(val):
        """Validate acceptable inputs for the name of the function"""
        acceptable_chars = ''.join([string.digits, string.letters, '_-'])
        if not set(str(val)).issubset(acceptable_chars):
            raise app_integration_parser.error('Name must contain only letters, numbers, '
                                               'hyphens, or underscores.')

        return val

    # App integration name to be used for this instance that must be unique per cluster
    app_integration_parser.add_argument(
        '--name', dest='app_name', required=True, help=ARGPARSE_SUPPRESS, type=_validate_name)


def _add_metrics_subparser(subparsers):
    """Add the metrics subparser: manage.py metrics [options]"""
    usage = 'manage.py metrics [options]'

    cluster_choices_block = '\n'.join('{:>28}{}'.format('', cluster) for cluster in CLUSTERS)

    description = """
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
    --debug             Enable debug logger output

Optional Arguemnts:

    -c/--clusters       Space delimited list of clusters to enable metrics for. If
                          omitted, this will enable metrics for all clusters. Choices are:
{}
Examples:

    manage.py metrics --enable --functions rule

""".format(version, cluster_choices_block)

    metrics_parser = _generate_subparser(subparsers, 'metrics', usage, description)

    # allow the user to select 1 or more functions to enable metrics for
    metrics_parser.add_argument(
        '-f',
        '--functions',
        choices=['rule', 'alert', 'athena'],
        help=ARGPARSE_SUPPRESS,
        nargs='+',
        action=NormalizeFunctionAction,
        required=True)

    # get the metric toggle value
    toggle_group = metrics_parser.add_mutually_exclusive_group(required=True)

    toggle_group.add_argument('-e', '--enable', dest='enable_metrics', action='store_true')

    toggle_group.add_argument('-d', '--disable', dest='enable_metrics', action='store_false')

    # allow the user to select 0 or more clusters to enable metrics for
    metrics_parser.add_argument(
        '-c',
        '--clusters',
        choices=CLUSTERS,
        help=ARGPARSE_SUPPRESS,
        nargs='+',
        action=UniqueSetAction,
        default=CLUSTERS)


def _add_metric_alarm_subparser(subparsers):
    """Add the create-alarm subparser: manage.py create-alarm [options]"""
    usage = 'manage.py create-alarm [options]'

    # get the available metrics to be used
    available_metrics = metrics.MetricLogger.get_available_metrics()
    all_metrics = [metric for func in available_metrics for metric in available_metrics[func]]
    metric_choices_block = '\n'.join('{:>35}{}'.format('', metric) for metric in all_metrics)
    cluster_choices_block = '\n'.join('{:>37}{}'.format('', cluster) for cluster in CLUSTERS)

    description = """
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
    --debug                      Enable debug logger output

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

""".format(version, metric_choices_block, cluster_choices_block)

    metric_alarm_parser = _generate_subparser(subparsers, 'create-alarm', usage, description)

    # add all the required parameters
    # add metrics for user to pick from. Will be mapped to 'metric_name' in terraform
    metric_alarm_parser.add_argument(
        '-m',
        '--metric',
        choices=all_metrics,
        dest='metric_name',
        help=ARGPARSE_SUPPRESS,
        required=True)

    # check to see what the user wants to apply this metric to (cluster, aggregate, or both)
    metric_alarm_parser.add_argument(
        '-mt',
        '--metric-target',
        choices=['cluster', 'aggregate', 'all'],
        help=ARGPARSE_SUPPRESS,
        required=True)

    # get the comparison type for this metric
    metric_alarm_parser.add_argument(
        '-co',
        '--comparison-operator',
        choices=[
            'GreaterThanOrEqualToThreshold', 'GreaterThanThreshold', 'LessThanThreshold',
            'LessThanOrEqualToThreshold'
        ],
        help=ARGPARSE_SUPPRESS,
        required=True)

    # get the name of the alarm
    def _alarm_name_validator(val):
        if not 1 <= len(val) <= 255:
            raise metric_alarm_parser.error('alarm name length must be between 1 and 255')
        return val

    metric_alarm_parser.add_argument(
        '-an', '--alarm-name', help=ARGPARSE_SUPPRESS, required=True, type=_alarm_name_validator)

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
        '-ep',
        '--evaluation-periods',
        help=ARGPARSE_SUPPRESS,
        required=True,
        type=_alarm_eval_periods_validator)

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
        '-p', '--period', help=ARGPARSE_SUPPRESS, required=True, type=_alarm_period_validator)

    # get the threshold for this alarm
    metric_alarm_parser.add_argument(
        '-t', '--threshold', help=ARGPARSE_SUPPRESS, required=True, type=float)

    # all other optional flags
    # get the optional alarm description
    def _alarm_description_validator(val):
        if len(val) > 1024:
            raise metric_alarm_parser.error('alarm description length must be less than 1024')
        return val

    metric_alarm_parser.add_argument(
        '-ad',
        '--alarm-description',
        help=ARGPARSE_SUPPRESS,
        type=_alarm_description_validator,
        default='')

    # allow the user to select 0 or more clusters to apply this alarm to
    metric_alarm_parser.add_argument(
        '-c',
        '--clusters',
        choices=CLUSTERS,
        help=ARGPARSE_SUPPRESS,
        nargs='+',
        action=UniqueSetAction,
        default=set())

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
        '-s',
        '--statistic',
        choices=['SampleCount', 'Average', 'Sum', 'Minimum', 'Maximum'],
        help=ARGPARSE_SUPPRESS,
        default='')


def _add_lambda_subparser(subparsers):
    """Add the Lambda subparser: manage.py lambda [subcommand] [options]"""
    usage = 'manage.py lambda [subcommand] [options]'
    description = """
StreamAlertCLI v{}
Deploy, Rollback, and Test StreamAlert Lambda functions

Available Subcommands:

    manage.py lambda deploy            Deploy Lambda functions
    manage.py lambda rollback          Rollback Lambda functions
    manage.py lambda test              Run rule tests

""".format(version)

    lambda_parser = _generate_subparser(subparsers, 'lambda', usage, description)

    lambda_subparsers = lambda_parser.add_subparsers()

    _add_lambda_deploy_subparser(lambda_subparsers)
    _add_lambda_rollback_subparser(lambda_subparsers)
    _add_lambda_test_subparser(lambda_subparsers)


def _add_lambda_deploy_subparser(subparsers):
    """Add the lambda deploy subparser: manage.py lambda deploy"""
    usage = 'manage.py lambda deploy'
    description = """
StreamAlertCLI v{}
Deploy Lambda functions

Command:

    manage.py lambda deploy            Deploy Lambda functions

Required Arguments:

    -p/--processor                     A list of the Lambda functions to deploy.
                                         Valid options include: rule, alert, athena, apps,
                                         all, or any combination of these.

Optional Arguments:

    --skip-rule-staging                Skip staging of new rules so they go directly into
                                         production.
    --stage-rules                      Stage the rules provided in a space-separated list
    --unstage-rules                    Unstage the rules provided in a space-separated list
    --debug                            Enable debug logger output

Examples:

    manage.py lambda deploy --processor rule alert

""".format(version)

    lambda_deploy_parser = _generate_subparser(subparsers, 'deploy', usage, description, True)

    # TODO (ryandeivert): the below change is temporary and allows
    # for using rule staging prior to having a promotion lambda in place
    # Remove this block when this feature is complete
    if not ENABLE_RULE_STAGING:
        lambda_deploy_parser.add_argument(
            '--stage-new-rules',
            action='store_false',
            dest='skip_rule_staging',
            help=ARGPARSE_SUPPRESS
        )
    else:
        # flag to manually bypass rule staging for new rules upon deploy
        lambda_deploy_parser.add_argument(
            '--skip-rule-staging',
            action='store_true',
            help=ARGPARSE_SUPPRESS
        )

    # flag to manually demote specific rules to staging during deploy
    lambda_deploy_parser.add_argument(
        '--stage-rules',
        action=MutuallyExclusiveStagingAction,
        default=set(),
        help=ARGPARSE_SUPPRESS,
        nargs='+'
    )

    # flag to manually bypass rule staging for specific rules during deploy
    lambda_deploy_parser.add_argument(
        '--unstage-rules',
        action=MutuallyExclusiveStagingAction,
        default=set(),
        help=ARGPARSE_SUPPRESS,
        nargs='+'
    )

    _add_default_lambda_args(lambda_deploy_parser)


def _add_lambda_rollback_subparser(subparsers):
    """Add the lambda rollback subparser: manage.py lambda rollback"""
    usage = 'manage.py lambda rollback'
    description = """
StreamAlertCLI v{}
Rollback Lambda functions

Command:

    manage.py lambda rollback          Rollback Lambda functions

Required Arguments:

    -p/--processor                     A list of the Lambda functions to rollback.
                                         Valid options include: rule, alert, athena, apps,
                                         all, or any combination of these.

Optional Arguments:

    --debug                            Enable debug logger output

Examples:

    manage.py lambda rollback --processor rule alert

""".format(version)

    lambda_rollback_parser = _generate_subparser(subparsers, 'rollback', usage, description, True)

    _add_default_lambda_args(lambda_rollback_parser)


def _add_lambda_test_subparser(subparsers):
    """Add the lambda test subparser: manage.py lambda test"""
    usage = 'manage.py lambda test'
    description = """
StreamAlertCLI v{}
Run rule tests

Command:

    manage.py lambda test              Run rule tests

Required Arguments:

    -p/--processor                     A list of the Lambda functions to test.
                                         Valid options include: rule, alert, all, or
                                         any combination of these.
    -r/--test-rules                    List of rules to test, separated by spaces.
                                         Cannot be used in conjunction with `--test-files`
    -f/--test-files                    List of files to test, separated by spaces.
                                         Cannot be used in conjunction with `--test-rules`
                                         This flag supports the full file name, with extension,
                                         or the base file name, without extension
                                         (ie: test_file_name.json or test_file_name).

Optional Arguments:

    --debug                            Enable debug logger output

Example:

    manage.py lambda test --processor rule --test-rules lateral_movement root_logins

""".format(version)

    lambda_test_parser = _generate_subparser(subparsers, 'test', usage, description, True)

    # require the name of the processor being tested
    lambda_test_parser.add_argument(
        '-p',
        '--processor',
        choices=['alert', 'all', 'rule'],
        help=ARGPARSE_SUPPRESS,
        nargs='+',
        action=UniqueSetAction,
        required=True)

    # flag to run additional stats during testing
    lambda_test_parser.add_argument(
        '-s',
        '--stats',
        action='store_true',
        help=ARGPARSE_SUPPRESS
    )

    # Validate the provided repitition value
    def _validate_repitition(val):
        """Make sure the input is between 1 and 1000"""
        err = ('Invalid repitition value [{}]. Must be an integer between 1 '
               'and 1000').format(val)
        try:
            count = int(val)
        except TypeError:
            raise lambda_test_parser.error(err)

        if not 1 <= count <= 1000:
            raise lambda_test_parser.error(err)

        return count

    # flag to run these tests a given number of times
    lambda_test_parser.add_argument(
        '-n',
        '--repeat',
        default=1,
        type=_validate_repitition,
        help=ARGPARSE_SUPPRESS
    )

    test_filter_group = lambda_test_parser.add_mutually_exclusive_group(required=False)

    # add the optional ability to test against a rule/set of rules
    test_filter_group.add_argument(
        '-f',
        '--test-files',
        dest='files',
        nargs='+',
        help=ARGPARSE_SUPPRESS,
        action=UniqueSetAction,
        default=set())

    # add the optional ability to test against a rule/set of rules
    test_filter_group.add_argument(
        '-r',
        '--test-rules',
        dest='rules',
        nargs='+',
        help=ARGPARSE_SUPPRESS,
        action=UniqueSetAction,
        default=set())


def _add_default_lambda_args(lambda_parser):
    """Add the default arguments to the lambda parsers"""

    # require the name of the processor being deployed/rolled back
    lambda_parser.add_argument(
        '-p', '--processor',
        choices=['all', 'alert', 'alert_merger', 'apps', 'athena', 'rule',
                 'threat_intel_downloader'],
        help=ARGPARSE_SUPPRESS,
        nargs='+',
        action=UniqueSetAction,
        required=True)

    lambda_parser.add_argument(
        '--clusters',
        help=ARGPARSE_SUPPRESS,
        nargs='+')


def _add_terraform_subparser(subparsers):
    """Add Terraform subparser: manage.py terraform [subcommand] [options]"""
    usage = 'manage.py terraform [subcommand] [options]'
    description = """
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
    --clusters                                  The StreamAlert cluster(s) to apply to.

Examples:

    manage.py terraform init
    manage.py terraform init-backend
    manage.py terraform generate

    manage.py terraform build
    manage.py terraform build --target kinesis
    manage.py terraform build --target stream_alert

    manage.py terraform destroy
    manage.py terraform destroy -target cloudtrail

""".format(version)

    tf_parser = _generate_subparser(subparsers, 'terraform', usage, description)

    # add subcommand options for the terraform sub-parser
    tf_parser.add_argument(
        'subcommand',
        choices=['build', 'clean', 'destroy', 'init', 'init-backend', 'generate', 'status'],
        help=ARGPARSE_SUPPRESS)

    tf_parser.add_argument(
        '--target',
        choices=[
            'athena', 'cloudwatch_monitoring', 'cloudtrail', 'flow_logs', 'kinesis',
            'kinesis_events', 'stream_alert', 's3_events', 'threat_intel_downloader'
        ],
        help=ARGPARSE_SUPPRESS,
        nargs='+')

    tf_parser.add_argument(
        '--clusters',
        action=UniqueSetAction,
        default=set(),
        help=ARGPARSE_SUPPRESS,
        nargs='+')


def _add_kinesis_subparser(subparsers):
    """Add kinesis subparser"""
    usage = 'manage.py kinesis [disable-events]'
    description = """
StreamAlertCLI v{}
Kinesis StreamAlert options

Update Kinesis settings and then runs Terraform

Available Commands:

    disable-events             Disable Kinesis Events
    enable-events              Enable Kinesis Events

Optional Arguments:

    --clusters                Space delimited set of clusters to modify, defaults to all
    --debug                   Enable debug logger output
    --skip-terraform          Only set the config, do not run Terraform after

Examples:

    manage.py kinesis disable-events --clusters corp prod

""".format(version)

    kinesis_parser = _generate_subparser(subparsers, 'kinesis', usage, description)

    kinesis_parser.add_argument(
        'subcommand',
        choices=['disable-events', 'enable-events'],
        help=ARGPARSE_SUPPRESS)

    kinesis_parser.add_argument(
        '-c',
        '--clusters',
        choices=CLUSTERS,
        help=ARGPARSE_SUPPRESS,
        nargs='+',
        action=UniqueSetAction,
        default=set())

    kinesis_parser.add_argument('--skip-terraform', action='store_true', help=ARGPARSE_SUPPRESS)


def _add_configure_subparser(subparsers):
    """Add configure subparser: manage.py configure [config_key] [config_value]"""
    usage = 'manage.py configure [config_key] [config_value]'
    description = """
StreamAlertCLI v{}
Configure StreamAlert options

Available Keys:

    prefix                     Resource prefix
    aws_account_id             AWS account number

Examples:

    manage.py configure prefix my-organization

""".format(version)

    configure_parser = _generate_subparser(subparsers, 'configure', usage, description)

    configure_parser.add_argument(
        'config_key', choices=['prefix', 'aws_account_id'], help=ARGPARSE_SUPPRESS)

    configure_parser.add_argument('config_value', help=ARGPARSE_SUPPRESS)


def _add_athena_subparser(subparsers):
    """Add athena subparser: manage.py athena [subcommand]"""
    usage = 'manage.py athena [subcommand]'
    description = """
StreamAlertCLI v{}
Athena StreamAlert options

Available Subcommands:

    manage.py athena init                     Initialize the Athena base config (for legacy support)
    manage.py athena create-table             Create an Athena table
    manage.py athena rebuild-partitions       Rebuild the partitions for an Athena table
    manage.py athena drop-all-tables          Drop all of the tables from the database

""".format(version)

    athena_parser = _generate_subparser(subparsers, 'athena', usage, description)

    athena_subparsers = athena_parser.add_subparsers()

    _add_athena_init_subparser(athena_subparsers)
    _add_athena_create_table_subparser(athena_subparsers)
    _add_athena_rebuild_subparser(athena_subparsers)
    _add_athena_drop_all_subparser(athena_subparsers)


def _add_athena_init_subparser(subparsers):
    """Add the athena init subparser: manage.py athena init"""
    usage = 'manage.py athena init'
    description = """
StreamAlertCLI v{}
Initialize the Athena base config

Command:

    manage.py athena init                Initialize the Athena base config that gets written
                                           to 'conf/lambda.json'.

Optional Arguments:

    --debug                              Enable debug logger output

""".format(version)

    _generate_subparser(subparsers, 'init', usage, description, True)


def _add_athena_create_table_subparser(subparsers):
    """Add the athena create-table subparser: manage.py athena create-table"""
    usage = 'manage.py athena create-table'
    description = """
StreamAlertCLI v{}
Create an Athena table

Command:

    manage.py athena create-table      Create an Athena table

Required Arguments:

    -b/--bucket                        The name of the S3 bucket to be used for Athena
                                         query results.
    -n/--table-name                    The name of the Athena table to create. This must be a
                                         type of log defined in logs.json

Optional Arguments:

    -s/--schema-override               List of value types to override in the schema
                                         The provided input should be space separated
                                         directives like "column_name=value_type"
    --debug                            Enable debug logger output

Examples:

    manage.py athena create-table \\
      --bucket s3.bucket.name \\
      --table-name my_athena_table

""".format(version)

    athena_create_table_parser = _generate_subparser(
        subparsers, 'create-table', usage, description, True)

    _add_default_athena_args(athena_create_table_parser)

    # Validate the provided schema-override options
    def _validate_override(val):
        """Make sure the input is in the format column_name=type"""
        err = ('Invalid override expression [{}]. The proper format is '
               '"column_name=value_type"').format(val)
        if not '=' in val:
            raise athena_create_table_parser.error(err)

        if len(val.split('=')) != 2:
            raise athena_create_table_parser.error(err)

    athena_create_table_parser.add_argument(
        '--schema-override',
        nargs='+',
        help=ARGPARSE_SUPPRESS,
        action=UniqueSetAction,
        default=set(),
        type=_validate_override)


def _add_athena_rebuild_subparser(subparsers):
    """Add the athena rebuild-partitions subparser: manage.py athena rebuild-partitions"""
    usage = 'manage.py athena rebuild-partitions'
    description = """
StreamAlertCLI v{}
Rebuild the partitions for an Athena table

Command:

    manage.py athena rebuild-partitions      Rebuilds the partitions for an Athena table

Required Arguments:

    -b/--bucket                        The name of the S3 bucket to be used for Athena
                                         query results.
    -n/--table-name                    The name of the Athena table to create. This must be
                                         either a type of log defined in logs.json or 'alerts'

Optional Arguments:

    --debug                            Enable debug logger output

Examples:

    manage.py athena rebuild-partitions \\
      --bucket s3.bucket.name \\
      --table-name my_athena_table

""".format(version)

    athena_rebuild_parser = _generate_subparser(
        subparsers, 'rebuild-partitions', usage, description, True)

    _add_default_athena_args(athena_rebuild_parser)


def _add_athena_drop_all_subparser(subparsers):
    """Add the athena drop-all-tables subparser: manage.py athena drop-all-tables"""
    usage = 'manage.py athena drop-all-tables'
    description = """
StreamAlertCLI v{}
Drop all tables from an Athena database

Command:

    manage.py athena drop-all-tables     Drop all of the tables from the database

Optional Arguments:

    --debug                              Enable debug logger output

""".format(version)

    _generate_subparser(subparsers, 'drop-all-tables', usage, description, True)


def _add_default_athena_args(athena_parser):
    """Adds the default required arguments for athena subcommands (bucket and table)"""

    athena_parser.add_argument(
        '-b', '--bucket',
        help=ARGPARSE_SUPPRESS,
        required=True)

    athena_parser.add_argument(
        '-n', '--table-name',
        help=ARGPARSE_SUPPRESS,
        required=True)


def _add_threat_intel_subparser(subparsers):
    """Add Threat Intel subparser: manage.py threat-intel [subcommand]"""
    usage = 'manage.py threat-intel [subcommand]'
    description = """
StreamAlertCLI v{}
Enable, configure StreamAlert Threat Intelligence feature.

Available Subcommands:

    manage.py threat-intel enable        Enable the Threat Intelligence feature in Rule Processor

    Optional Arguments:
        --dynamodb-table   The DynamoDB table name which stores IOC(s).

Examples:

    manage.py threat-intel enable
    manage.py threat-intel enable --dynamodb-table my_ioc_table
""".format(version)

    threat_intel_parser = _generate_subparser(subparsers, 'threat-intel', usage, description)

    threat_intel_parser.add_argument(
        'subcommand', choices=['enable'], help=ARGPARSE_SUPPRESS
    )

    threat_intel_parser.add_argument(
        '--dynamodb-table',
        help=ARGPARSE_SUPPRESS
    )


def _add_threat_intel_downloader_subparser(subparsers):
    """Add threat intel downloader subparser: manage.py threat-intel-downloader [subcommand]"""
    usage = 'manage.py threat-intel-downloader [subcommand]'
    description = """
StreamAlertCLI v{}
Lambda function to retrieve IOC(s) from 3rd party threat feed vendor.

Available Subcommands:

    manage.py threat-intel-downloader enable        Enable the Threat Intel Downloader Lambda function

    Required Arguments:

        --timeout           The AWS Lambda function timeout value, in seconds. This should
                              be an integer between 10 and 300.
        --memory            The AWS Lambda function max memory value, in megabytes. This should
                              be an integer between 128 and 1536.
        --interval          The interval, defined using a 'rate' expression, at
                              which this app integration function should execute. Examples of
                              acceptable input are:
                                'rate(1 hour)'          # Every hour (note the singular 'hour')
                                'rate(1 day)'           # Every day
                                'rate(2 days)'          # Every 2 days

                              See the link in the Resources section below for more information.
    Optional Arguments:
        --table_rcu          The DynamoDB table Read Capacity Unit. Default is 10.
        --table_wcu          The DynamoDB table Write Capacity Unit. Default is 10.
        --ioc_keys           The keys (list) of IOC stored in DynamoDB table.
        --ioc_filters        Filters (list) applied while retrieving IOCs from Threat Feed.
        --ioc_types          IOC types (list) are defined by the Threat Feed. IOC types can be
                             different from different Threat Feeds.
        --excluded_sub_types Sub ioc types want to excluded. Default it will exclude 'bot_ip', 'brute_ip', 'scan_ip', 'spam_ip', 'tor_ip'.
        --min_read_capacity  Maximal read capacity when autoscale enabled, default is 5.
        --max_read_capacity  Mimimal read capacity when autoscale enabled, default is 5.
        --target_utilization Utilization remains at or near the setting level when autoscale enabled.

    manage.py threat-intel-downloader update-auth   Update API credentials to parameter store.

Examples:

    manage.py threat-intel-downloader enable \\
    --interval 'rate(1 day)' \\
    --timeout 120 \\
    --memory 128
""".format(version)

    ti_downloader_parser = _generate_subparser(
        subparsers, 'threat-intel-downloader', usage, description)

    ti_downloader_parser.add_argument(
        'subcommand', choices=['enable', 'update-auth'], help=ARGPARSE_SUPPRESS
    )

    # Validate the rate at which this should run
    def _validate_scheduled_interval(val):
        """Validate acceptable inputs for the schedule expression
        These follow the format 'rate(5 minutes)'
        """
        rate_match = AWS_RATE_RE.match(val)
        if rate_match:
            return val

        if val.startswith('rate('):
            err = ('Invalid rate expression \'{}\'. For help see {}'
                   .format(val, '{}#RateExpressions'.format(AWS_RATE_HELPER)))
            raise ti_downloader_parser.error(err)

        raise ti_downloader_parser.error('Invalid expression \'{}\'. For help '
                                         'see {}'.format(val, AWS_RATE_HELPER))

    ti_downloader_parser.add_argument(
        '--interval', help=ARGPARSE_SUPPRESS, type=_validate_scheduled_interval
    )

    # Validate the timeout value to make sure it is between 10 and 300
    def _validate_timeout(val):
        """Validate acceptable inputs for the timeout of the function"""
        error = 'The \'timeout\' value must be an integer between 10 and 300'
        try:
            timeout = int(val)
        except ValueError:
            raise ti_downloader_parser.error(error)

        if not 10 <= timeout <= 300:
            raise ti_downloader_parser.error(error)

        return timeout

    ti_downloader_parser.add_argument(
        '--timeout', help=ARGPARSE_SUPPRESS, type=_validate_timeout
    )

    # Validate the memory value to make sure it is between 128 and 1536
    def _validate_memory(val):
        """Validate acceptable inputs for the memory of the function"""
        error = 'The \'memory\' value must be an integer between 128 and 1536'
        try:
            memory = int(val)
        except ValueError:
            raise ti_downloader_parser.error(error)

        if not 128 <= memory <= 1536:
            raise ti_downloader_parser.error(error)

        return memory

    ti_downloader_parser.add_argument(
        '--memory', help=ARGPARSE_SUPPRESS, type=_validate_memory
    )

    ti_downloader_parser.add_argument(
        '--table_rcu', help=ARGPARSE_SUPPRESS, default=10
    )

    ti_downloader_parser.add_argument(
        '--table_wcu', help=ARGPARSE_SUPPRESS, default=10
    )

    ti_downloader_parser.add_argument(
        '--ioc_keys',
        help=ARGPARSE_SUPPRESS,
        default=['expiration_ts', 'itype', 'source', 'type', 'value']
    )

    ti_downloader_parser.add_argument(
        '--ioc_filters',
        help=ARGPARSE_SUPPRESS,
        default=['crowdstrike', '@airbnb.com']
    )

    ti_downloader_parser.add_argument(
        '--ioc_types',
        help=ARGPARSE_SUPPRESS,
        default=['domain', 'ip', 'md5']
    )

    ti_downloader_parser.add_argument(
        '--excluded_sub_types',
        help=ARGPARSE_SUPPRESS,
        default=['bot_ip', 'brute_ip', 'scan_ip', 'spam_ip', 'tor_ip']
    )

    ti_downloader_parser.add_argument(
        '--autoscale',
        help=ARGPARSE_SUPPRESS,
        default=False,
        action='store_true'
    )

    ti_downloader_parser.add_argument(
        '--max_read_capacity', help=ARGPARSE_SUPPRESS, default=5
    )

    ti_downloader_parser.add_argument(
        '--min_read_capacity', help=ARGPARSE_SUPPRESS, default=5
    )

    ti_downloader_parser.add_argument(
        '--target_utilization', help=ARGPARSE_SUPPRESS, default=70
    )


def _add_rule_table_subparser(subparsers):
    """Add the rule database helper subparser: manage.py rule-table [subcommand] [options]"""
    usage = 'manage.py rule-table [subcommand] [options]'
    description = """
StreamAlertCLI v{}
Print the status of or update remote StreamAlert rule information within the rule database

Available Subcommands:

    manage.py rule-table status          List the current staging status from the rules databse
    manage.py rule-table stage           Stage the rules provided in a space-separated list
    manage.py rule-table unstage         Unstage the rules provided in a space-separated list

""".format(version)

    rule_table_parser = _generate_subparser(subparsers, 'rule-table', usage, description)

    rule_table_subparsers = rule_table_parser.add_subparsers()

    _add_rule_table_status_subparser(rule_table_subparsers)
    _add_rule_table_stage_subparser(rule_table_subparsers)
    _add_rule_table_unstage_subparser(rule_table_subparsers)

def _add_rule_table_status_subparser(subparsers):
    """Add the rule db status subparser: manage.py rule-table status"""
    usage = 'manage.py rule-table status'
    description = """
StreamAlertCLI v{}
List all rules within the rule database and their staging status

Command:

    manage.py rule-table status       List rules in the rule database with their staging status

Optional Arguments:

    --verbose           Output additional information for rules in the database
    --debug             Enable debug logger output

""".format(version)

    rule_table_status_parser = _generate_subparser(subparsers, 'status', usage, description, True)

    rule_table_status_parser.add_argument('--verbose', action='store_true', help=ARGPARSE_SUPPRESS)


def _add_rule_table_stage_subparser(subparsers):
    """Add the rule db stage subparser: manage.py rule-table stage"""
    usage = 'manage.py rule-table stage'
    description = """
StreamAlertCLI v{}
Stage rules given their name as a space-separated list

Command:

    manage.py rule-table stage         Stage the rules provided in a space-separated list

Optional Arguments:

    --debug                            Enable debug logger output

""".format(version)

    rule_table_stage_parser = _generate_subparser(subparsers, 'stage', usage, description, True)

    _add_default_rule_table_staging_args(rule_table_stage_parser)


def _add_rule_table_unstage_subparser(subparsers):
    """Add the rule db unstage subparser: manage.py rule-table unstage"""
    usage = 'manage.py rule-table unstage'
    description = """
StreamAlertCLI v{}
Unstage rules given their name as a space-separated list

Command:

    manage.py rule-table unstage       Unstage the rules provided in a space-separated list

Optional Arguments:

    --debug                            Enable debug logger output

""".format(version)

    rule_table_unstage_parser = _generate_subparser(
        subparsers, 'unstage', usage, description, True)

    _add_default_rule_table_staging_args(rule_table_unstage_parser)


def _add_default_rule_table_staging_args(subparser):
    """Add the default arguments to the rule table staging parsers"""
    subparser.add_argument(
        'rules',
        action=UniqueSetAction,
        default=set(),
        help=ARGPARSE_SUPPRESS,
        nargs='+'
    )


def build_parser():
    """Build the argument parser."""
    usage = '%(prog)s [command] [subcommand] [options]'
    description = """
StreamAlertCLI v{}
Build, Deploy, Configure, and Test StreamAlert Infrastructure

Available Commands:

    manage.py app                        Create, list, or update a StreamAlert app integration function
    manage.py athena                     Configure Athena for StreamAlert
    manage.py configure                  Configure Global StreamAlert settings
    manage.py create-alarm               Add a CloudWatch alarm for predefined metrics
    manage.py kinesis                    Configure Kinesis for StreamAlert
    manage.py lambda                     Deploy, test, and rollback StreamAlert AWS Lambda functions
    manage.py live-test                  Send alerts to configured outputs
    manage.py metrics                    Enable or disable metrics for all lambda functions
    manage.py output                     Configure new StreamAlert outputs
    manage.py rule-table                 Get the status of or update rules in the rules database
    manage.py terraform                  Manage StreamAlert infrastructure
    manage.py threat-intel               Enable, configure StreamAlert Threat Intelligence feature.
    manage.py threat-intel-downloader    Lambda function to retrieve IOC(s).
    manage.py validate-schemas           Run validation of schemas

For additional details on the available commands, try:

    manage.py [command] --help

""".format(version)

    parser = ArgumentParser(
        description=description,
        prog='manage.py',
        usage=usage,
        formatter_class=RawTextHelpFormatter)

    parser.add_argument(
        '-v', '--version',
        action='version',
        version='StreamAlert v{}'.format(version)
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
    _add_app_integration_subparser(subparsers)
    _add_kinesis_subparser(subparsers)
    _add_threat_intel_subparser(subparsers)
    _add_threat_intel_downloader_subparser(subparsers)
    _add_rule_table_subparser(subparsers)

    return parser


def main():
    """Entry point for the CLI."""
    parser = build_parser()
    options = parser.parse_args()
    cli_runner(options)
    LOGGER_CLI.info('Completed')


if __name__ == "__main__":
    main()

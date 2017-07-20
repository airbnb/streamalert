'''
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
'''

import json
import logging
import os
import re
import sys
import time

from collections import namedtuple
from mock import Mock, patch

import boto3
from moto import mock_lambda, mock_kms, mock_s3, mock_sns

from stream_alert.alert_processor import main as StreamOutput
from stream_alert.rule_processor.handler import StreamAlert
from stream_alert_cli import helpers
from stream_alert_cli.logger import LOGGER_CLI, LOGGER_SA, LOGGER_SO
from stream_alert_cli.outputs import load_outputs_config


# import all rules loaded from the main handler
# pylint: disable=unused-import
import stream_alert.rule_processor.main
# pylint: enable=unused-import

DIR_RULES = 'test/integration/rules'
COLOR_RED = '\033[0;31;1m'
COLOR_YELLOW = '\033[0;33;1m'
COLOR_GREEN = '\033[0;32;1m'
COLOR_RESET = '\033[0m'


class TestingSuppressFilter(logging.Filter):
    """Simple logging filter for suppressing specific log messagses that we
    do not want to print during testing. Add any suppressions to the tuple.
    """

    def filter(self, record):
        suppress_starts_with = (
            'Starting download from S3',
            'Completed download in'
        )
        return not record.getMessage().startswith(suppress_starts_with)


class RuleProcessorTester(object):
    """Class to encapsulate testing the rule processor"""

    def __init__(self, print_output):
        """RuleProcessorTester initializer

        Args:
            print_output [bool]: Boolean indicating whether this processor test
                should print results to stdout. This is set to false when the
                alert processor is explicitly being testing alone, and set to
                true for rule processor tests and end-to-end tests.
                Warnings and errors captrued during rule processor testing
                will still be written to stdout regardless of this setting.
        """
        # Create the topic used for the mocking of alert sending
        # This is used in stream_alert/rule_processor/sink.py to 'send' alerts
        sns_client = boto3.client('sns', region_name='us-east-1')
        sns_client.create_topic(Name='test_streamalerts')
        # Create a list for pass/fails. The first value in the list is a
        # list of tuples for failures, and the second is list of tuples for
        # passes. Tuple is (rule_name, rule_description)
        self.rules_fail_pass_warn = ([], [], [])
        self.print_output = print_output

    def test_processor(self, rules):
        """Perform integration tests for the 'rule' Lambda function

        Args:
            rules [list or None]: Specific rule names (or None) to restrict
                testing to. This is passed in from the CLI using the --rules option.

        Returns:
            [generator] yields a tuple containig a boolean of test status and
                a list of alerts to run through the alert processor
        """
        all_tests_passed = True

        for rule_file, rule_name in get_rule_test_files(rules):
            with open(os.path.join(DIR_RULES, rule_file), 'r') as rule_file_handle:
                try:
                    contents = json.load(rule_file_handle)
                except (ValueError, TypeError) as err:
                    all_tests_passed = False
                    message = 'Improperly formatted file - {}: {}'.format(
                        type(err).__name__, err)
                    self.rules_fail_pass_warn[2].append((rule_name, message))
                    continue

            test_records = contents.get('records')
            if not test_records:
                all_tests_passed = False
                self.rules_fail_pass_warn[2].append(
                    (rule_name, 'No records to test in file'))
                continue

            print_header = True
            # Go over the records and test the applicable rule
            for test_record in test_records:
                if not self.check_keys(rule_name, test_record):
                    all_tests_passed = False
                    continue

                self.apply_helpers(test_record)

                # Run tests on the formatted record
                alerts, expected_alerts = self.test_rule(
                    rule_name,
                    test_record,
                    helpers.format_lambda_test_record(test_record))

                current_test_passed = len(alerts) == expected_alerts

                # Print rule name for section header, but only if we get
                # to a point where there is a record to actually be tested.
                # This avoids potentialy blank sections
                if print_header:
                    if alerts or self.print_output:
                        print '\n{}'.format(rule_name)
                        print_header = not print_header

                if self.print_output:
                    report_output([
                        current_test_passed,
                        '[trigger={}]'.format(expected_alerts),
                        'rule',
                        test_record['service'],
                        test_record['description']])

                all_tests_passed = current_test_passed and all_tests_passed

                # yield the result and alerts back to caller
                yield all_tests_passed, alerts

                # Add the name of the rule to the applicable pass or fail list
                self.rules_fail_pass_warn[current_test_passed].append(
                    (rule_name, 'Rule failure: {}'.format(test_record['description'])))

        # Report on the final test results
        self.report_output_summary()

    def check_keys(self, rule_name, test_record):
        """Check the test_record contains the required keys

        Args:
            rule_name: The name of the rule being tested. This is passed in
                here strictly for reporting any errors with key checks.
            test_record [dict]: Test record metadata dict

        Returns:
            [bool] boolean result indicating if the proper keys are present
        """
        required_keys = {'data', 'description', 'service', 'source', 'trigger'}

        record_keys = set(test_record.keys())
        if not required_keys.issubset(record_keys):
            req_key_diff = required_keys.difference(record_keys)
            missing_keys = ','.join('\'{}\''.format(key) for key in req_key_diff)
            message = 'Missing required key(s) in log: {}'.format(missing_keys)
            self.rules_fail_pass_warn[0].append((rule_name, message))
            return False

        optional_keys = {'trigger_count', 'compress'}

        key_diff = record_keys.difference(required_keys | optional_keys)

        # Log a warning if there are extra keys declared in the test log
        if key_diff:
            extra_keys = ','.join('\'{}\''.format(key) for key in key_diff)
            message = 'Additional unnecessary keys in log: {}'.format(extra_keys)
            # Remove the key(s) and just warn the user that they are extra
            record_keys.difference_update(key_diff)
            self.rules_fail_pass_warn[2].append((rule_name, message))

        return record_keys.issubset(required_keys | optional_keys)

    @staticmethod
    def apply_helpers(test_record):
        """Detect and apply helper functions to test fixtures
        Helpers are declared in test fixtures via the following keyword:
        "<helpers:helper_name>"

        Supported helper functions:
            last_hour: return the current epoch time minus 60 seconds to pass the
                       last_hour rule helper.
        Args:
            test_record: loaded fixture file JSON as a dict.
        """
        # declare all helper functions here, they should always return a string
        helpers = {
            'last_hour': lambda: str(int(time.time()) - 60)
        }
        helper_regex = re.compile(r'\<helper:(?P<helper>\w+)\>')

        def find_and_apply_helpers(test_record):
            """Apply any helpers to the passed in test_record"""
            for key, value in test_record.iteritems():
                if isinstance(value, str) or isinstance(value, unicode):
                    test_record[key] = re.sub(
                        helper_regex,
                        lambda match: helpers[match.group('helper')](),
                        test_record[key]
                    )
                elif isinstance(value, dict):
                    find_and_apply_helpers(test_record[key])

        find_and_apply_helpers(test_record)

    def report_output_summary(self):
        """Helper function to print the summary results of all rule tests"""
        failed_tests = len(self.rules_fail_pass_warn[0])
        passed_tests = len(self.rules_fail_pass_warn[1])
        total_tests = failed_tests + passed_tests

        # Print some lines at the bottom of output to make it more readable
        # This occurs here so there is always space and not only when the
        # successful test info prints
        print '\n\n'

        # Only print success info if we explicitly want to print output
        # but always print any errors or warnings below
        if self.print_output:
            # Print a message indicating how many of the total tests passed
            print '{}({}/{})\tRule Tests Passed{}'.format(
                COLOR_GREEN, passed_tests, total_tests, COLOR_RESET)

        # Check if there were failed tests and report on them appropriately
        if self.rules_fail_pass_warn[0]:
            color = COLOR_RED
            # Print a message indicating how many of the total tests failed
            print '{}({}/{})\tRule Tests Failed'.format(color, failed_tests, total_tests)

            # Iterate over the rule_name values in the failed list and report on them
            for index, failure in enumerate(self.rules_fail_pass_warn[0]):
                if index == failed_tests - 1:
                    # Change the color back so std out is not red
                    color = COLOR_RESET
                print '\t({}/{}) [{}] {}{}'.format(
                    index + 1, failed_tests, failure[0], failure[1], color)

        # Check if there were any warnings and report on them
        if self.rules_fail_pass_warn[2]:
            color = COLOR_YELLOW
            warning_count = len(self.rules_fail_pass_warn[2])
            print '{}{} \tRule Warning{}'.format(color, warning_count, ('', 's')[warning_count > 1])

            for index, failure in enumerate(self.rules_fail_pass_warn[2]):
                if index == warning_count - 1:
                    # Change the color back so std out is not yellow
                    color = COLOR_RESET
                print '\t({}/{}) [{}] {}{}'.format(index + 1, warning_count, failure[0],
                                                   failure[1], color)

    @staticmethod
    def test_rule(rule_name, test_record, formatted_record):
        """Feed formatted records into StreamAlert and check for alerts
        Args:
            rule_name [str]: The rule name being tested
            test_record [dict]: A single record to test
            formatted_record [dict]: A properly formatted version of
                record for the service to be tested

        Returns:
            [bool] boolean indicating if this rule passed
        """
        event = {'Records': [formatted_record]}

        expected_alert_count = test_record.get('trigger_count')
        if not expected_alert_count:
            expected_alert_count = (0, 1)[test_record['trigger']]

        # Run the rule processor. Passing 'None' for context
        # will load a mocked object later
        alerts = StreamAlert(None, True).run(event)

        # we only want alerts for the specific rule being tested
        alerts = [alert for alert in alerts
                  if alert['metadata']['rule_name'] == rule_name]

        return alerts, expected_alert_count


class AlertProcessorTester(object):
    """Class to encapsulate testing the alert processor"""
    _alert_fail_pass = [0, 0]

    def __init__(self, context):
        """AlertProcessorTester initializer

        Args:
            context [namedtuple]: Constructed aws context object. The
                namedtuple contains an attribute of `mocked` that indicates
                if all dispatch calls should be mocked out instead of actually
                performed. If not mocked, the tests will attempt to actually
                send alerts to outputs.
        """
        self.context = context
        self.kms_alias = 'alias/stream_alert_secrets_test'
        self.secrets_bucket = 'test.streamalert.secrets'
        self.outputs_config = load_outputs_config()

    def test_processor(self, alerts):
        """Perform integration tests for the 'alert' Lambda function. Alerts
        that are fed through this are resultant from the rule processor tests.
        In order to end up here, the log must be configured to trigger a rule
        that would result in an alert being sent.

        Args:
            alerts [list]: list of alerts to be processed that have been fed in
                from the rule processor.

        Return:
            [bool] boolean indicating the status of the alert processor dispatching
        """
        status = True
        # Set the logger level to info so its not too noisy
        StreamOutput.LOGGER.setLevel(logging.ERROR)
        for alert in alerts:
            if self.context.mocked:
                self.setup_outputs(alert)

            for passed, output in StreamOutput.handler(alert, self.context):
                status = status and passed
                service, descriptor = output.split(':')
                message = 'sending alert to \'{}\''.format(descriptor)
                report_output([
                    passed,
                    '',
                    'alert',
                    service,
                    message
                ])

                self._alert_fail_pass[passed] += 1

        return status

    @classmethod
    def report_output_summary(cls):
        """Helper function to print the summary results of all alert tests"""
        failed_tests = cls._alert_fail_pass[0]
        passed_tests = cls._alert_fail_pass[1]
        total_tests = failed_tests + passed_tests

        # Print a message indicating how many of the total tests passed
        print '{}({}/{})\tAlert Tests Passed{}'.format(
            COLOR_GREEN, passed_tests, total_tests, COLOR_RESET)

        # Check if there were failed tests and report on them appropriately
        if failed_tests:
            # Print a message indicating how many of the total tests failed
            print '{}({}/{})\tAlert Tests Failed{}'.format(
                COLOR_RED, failed_tests, total_tests, COLOR_RESET)

    def setup_outputs(self, alert):
        """Helper function to handler any output setup"""
        outputs = alert['metadata'].get('outputs', [])
        # Patch the urllib2.urlopen event to override HTTPStatusCode, etc
        url_mock = Mock()
        patch('urllib2.urlopen', url_mock).start()
        for output in outputs:
            try:
                service, descriptor = output.split(':')
            except ValueError:
                continue

            if service == 'aws-s3':
                bucket = self.outputs_config[service][descriptor]
                boto3.client('s3', region_name='us-east-1').create_bucket(Bucket=bucket)
            elif service == 'aws-lambda':
                function = self.outputs_config[service][descriptor]
                parts = function.split(':')
                if len(parts) == 2 or len(parts) == 8:
                    function = parts[-2]
                else:
                    function = parts[-1]
                helpers.create_lambda_function(function, 'us-east-1')
            elif service == 'pagerduty':
                output_name = ('/').join([service, descriptor])
                creds = {'service_key': '247b97499078a015cc6c586bc0a92de6'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       'us-east-1', self.kms_alias)

                # Set the patched urlopen.getcode return value to 200
                url_mock.return_value.getcode.return_value = 200
            elif service == 'phantom':
                output_name = ('/').join([service, descriptor])
                creds = {'ph_auth_token': '6c586bc047b9749a92de29078a015cc6',
                         'url': 'phantom.foo.bar'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       'us-east-1', self.kms_alias)

                # Set the patched urlopen.getcode return value to 200
                url_mock.return_value.getcode.return_value = 200
                # Phantom needs a container 'id' value in the http response
                url_mock.return_value.read.return_value = '{"id": 1948}'
            elif service == 'slack':
                output_name = ('/').join([service, descriptor])
                creds = {'url': 'https://api.slack.com/web-hook-key'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       'us-east-1', self.kms_alias)

                # Set the patched urlopen.getcode return value to 200
                url_mock.return_value.getcode.return_value = 200


def report_output(cols):
    """Helper function to pretty print columns for reporting results
    Args:
        cols [list]: A list of columns to print as output
    """

    status = ('{}[Fail]{}'.format(COLOR_RED, COLOR_RESET),
              '{}[Pass]{}'.format(COLOR_GREEN, COLOR_RESET))[cols[0]]

    print '\t{}{:>14}\t{}\t({}): {}'.format(status, *cols[1:])


def get_rule_test_files(filter_rules):
    """Helper to get rule files to be tested

    Args:
        filter_rules [str]: Comma separated list of rules to run tests against

    Returns:
        [generator] Yields back the rule file path and rule name
    """
    for _, _, test_rule_files in os.walk(DIR_RULES):
        for rule_file in test_rule_files:
            rule_name = rule_file.split('.')[0]

            # If specific rules are being tested, skip files
            # that do not match those rules
            if filter_rules and rule_name not in filter_rules:
                continue

            yield rule_file, rule_name


def mock_me(context):
    """Decorator function for wrapping framework in mock calls
    for running local tests, and omitting mocks if testing live

    Args:
        context [namedtuple]: A constructed aws context object
    """
    def wrap(func):
        """Wrap the returned function with or without mocks"""
        if context.mocked:
            @mock_lambda
            @mock_sns
            @mock_s3
            @mock_kms
            def mocked(options, context):
                """This function is now mocked using moto mock decorators to
                override any boto3 calls. Wrapping this function here allows
                us to mock out all calls that happen below this scope."""
                return func(options, context)
            return mocked
        else:
            def unmocked(options, context):
                """This function will remain unmocked and operate normally"""
                return func(options, context)
            return unmocked

    return wrap

def get_context_from_config(cluster, config):
    """Return a constructed context to be used for testing

    Args:
        cluster [str]: Name of the cluster to be used for live testing
        config [CLIConfig]: Configuration for this StreamAlert setup that
            includes cluster info, etc that can be used for constructing
            an aws context object
    """
    context = namedtuple('aws_context', ['invoked_function_arn',
                                         'function_name'
                                         'mocked'])

    # Return a mocked context if the cluster is not provided
    # Otherwise construct the context from the config using the cluster
    if not cluster:
        context.invoked_function_arn = (
            'arn:aws:lambda:us-east-1:0123456789012:'
            'function:streamalert_alert_processor:production')
        context.function_name = 'test_streamalert_alert_processor'
        context.mocked = True
    else:
        prefix = config['global']['account']['prefix']
        account = config['global']['account']['aws_account_id']
        region = config['global']['account']['region']
        function_name = '{}_{}_streamalert_alert_processor'.format(prefix, cluster)
        arn = 'arn:aws:lambda:{}:{}:function:{}:testing'.format(
            region, account, function_name)

        context.invoked_function_arn = arn
        context.function_name = function_name
        context.mocked = False

    return context

def stream_alert_test(options, config=None):
    """High level function to wrap the integration testing entry point.
    This encapsulates the testing function and is used to specify if calls
    should be mocked.

    Args:
        options [namedtuple]: CLI options (debug, processor, etc)
        config [CLIConfig]: Configuration for this StreamAlert setup that
            includes cluster info, etc that can be used for constructing
            an aws context object
    """
    # get the options in a dictionary so we can do easy lookups
    run_options = vars(options)
    context = get_context_from_config(run_options.get('cluster'), config)

    @mock_me(context)
    def run_tests(options, context):
        """Actual protected function for running tests

        Args:
            options [namedtuple]: CLI options (debug, processor, etc)
            context [namedtuple]: A constructed aws context object
        """
        # Instantiate two status items - one for the rule processor
        # and one for the alert processor
        rp_status, ap_status = True, True

        if options.debug:
            LOGGER_SA.setLevel(logging.DEBUG)
            LOGGER_SO.setLevel(logging.DEBUG)
            LOGGER_CLI.setLevel(logging.DEBUG)
        else:
            # Add a filter to suppress a few noisy log messages
            LOGGER_SA.addFilter(TestingSuppressFilter())

        # Check if the rule processor should be run for these tests
        test_rules = (run_options.get('processor') in {'rule', 'all'} or
                      run_options.get('command') == 'live-test')

        # Check if the alert processor should be run for these tests
        test_alerts = (run_options.get('processor') in {'alert', 'all'} or
                       run_options.get('command') == 'live-test')

        rule_proc_tester = RuleProcessorTester(test_rules)
        # Run the rule processor for all rules or designated rule set
        for status, alerts in rule_proc_tester.test_processor(options.rules):
            # If the alert processor should be tested, pass any alerts to it
            # and store the status over time
            if test_alerts:
                # Update the overall alert processor status with the ongoing status
                ap_status = AlertProcessorTester(
                    context).test_processor(alerts) and ap_status

            # Update the overall rule processor status with the ongoing status
            rp_status = status and rp_status

        # Report summary information for the alert processor if it was ran
        if test_alerts:
            AlertProcessorTester.report_output_summary()

        if not (rp_status and ap_status):
            sys.exit(1)

    run_tests(options, context)

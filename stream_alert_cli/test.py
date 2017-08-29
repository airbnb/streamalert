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
from collections import namedtuple
import json
import logging
import os
import re
import sys
import time

import boto3
from mock import Mock, patch

from stream_alert.alert_processor import main as StreamOutput
from stream_alert.rule_processor.handler import StreamAlert
# import all rules loaded from the main handler
import stream_alert.rule_processor.main  # pylint: disable=unused-import
from stream_alert.rule_processor.payload import load_stream_payload
from stream_alert.rule_processor.rules_engine import StreamRules
from stream_alert_cli import helpers
from stream_alert_cli.logger import (
    get_log_memory_hanlder,
    LOGGER_CLI,
    LOGGER_SA,
    LOGGER_SH,
    LOGGER_SO,
    SuppressNoise
)

from stream_alert_cli.outputs import load_outputs_config

DIR_RULES = 'tests/integration/rules'
COLOR_RED = '\033[0;31;1m'
COLOR_YELLOW = '\033[0;33;1m'
COLOR_GREEN = '\033[0;32;1m'
COLOR_RESET = '\033[0m'

StatusMessageBase = namedtuple('StatusMessage', 'type, rule, message')

class StatusMessage(StatusMessageBase):
    """Simple class to encapsulate a status message"""
    WARNING = -1
    FAILURE = 0
    SUCCESS = 1


class RuleProcessorTester(object):
    """Class to encapsulate testing the rule processor"""

    def __init__(self, context, print_output):
        """RuleProcessorTester initializer

        Args:
            print_output (bool): Whether this processor test
                should print results to stdout. This is set to false when the
                alert processor is explicitly being testing alone, and set to
                true for rule processor tests and end-to-end tests.
                Warnings and errors captrued during rule processor testing
                will still be written to stdout regardless of this setting.
        """
        # Create the RuleProcessor. Passing a mocked context object with fake
        # values and False for suppressing sending of alerts to alert processor
        self.processor = StreamAlert(context, False)
        # Use a list of status_messages to store pass/fail/warning info
        self.status_messages = []
        self.total_tests = 0
        self.all_tests_passed = True
        self.print_output = print_output

    def test_processor(self, filter_rules, validate_only=False):
        """Perform integration tests for the 'rule' Lambda function

        Args:
            filter_rules (list|None): Specific rule names (or None) to restrict
                testing to. This is passed in from the CLI using the --rules option.
            validate_only (bool): If true, validation of test records will occur
                without the rules engine being applied to events.

        Yields:
            tuple (bool, list) or None: If testing rules, this yields a tuple containig a
                boolean of test status and a list of alerts to run through the alert
                processor. If validating test records only, this does not yield.
        """
        for rule_name, contents in self._get_rule_test_files(filter_rules, validate_only):
            # Go over the records and test the applicable rule
            for index, test_record in enumerate(contents.get('records')):
                self.total_tests += 1

                if not self.check_keys(rule_name, test_record):
                    self.all_tests_passed = False
                    continue

                self.apply_helpers(test_record)

                print_header_line = index == 0

                formatted_record = helpers.format_lambda_test_record(test_record)

                if validate_only:
                    self._validate_test_records(rule_name, test_record,
                                                formatted_record, print_header_line)
                    continue

                yield self._run_rule_tests(rule_name, test_record,
                                           formatted_record, print_header_line)

        # Report on the final test results
        self.report_output_summary()

    def _validate_test_records(self, rule_name, test_record, formatted_record, print_header_line):
        """Function to validate test records and log any errors

        Args:
            rule_name (str): The rule name being tested
            test_record (dict): A single record to test
            formatted_record (dict): A dictionary that includes the 'data' from the
                test record, formatted into a structure that is resemblant of how
                an incoming record from a service would format it.
                See test/integration/templates for example of how each service
                formats records.
        """
        service, entity = self.processor.classifier.extract_service_and_entity(formatted_record)

        if not self.processor.classifier.load_sources(service, entity):
            self.all_tests_passed = False
            return

        # Create the StreamPayload to use for encapsulating parsed info
        payload = load_stream_payload(service, entity, formatted_record)
        if not payload:
            self.all_tests_passed = False
            return

        if print_header_line:
            print '\n{}'.format(rule_name)

        for record in payload.pre_parse():
            self.processor.classifier.classify_record(record)

            if not record.valid:
                self.all_tests_passed = False
                self.analyze_record_delta(rule_name, test_record)

            report_output(record.valid, [
                '[log=\'{}\']'.format(record.log_source or 'unknown'),
                'validation',
                record.service(),
                test_record['description']])

    def _run_rule_tests(self, rule_name, test_record, formatted_record, print_header_line):
        """Run tests on a test record for a given rule

        Args:
            rule_name (str): The name of the rule being tested.
            test_record (dict): The loaded test event from json
            formatted_record (dict): A dictionary that includes the 'data' from the
                test record, formatted into a structure that is resemblant of how
                an incoming record from a service would format it.
                See test/integration/templates for example of how each service
                formats records.
            print_header_line (bool): Indicates if this is the first record from
                a test file, and therefore we should print some header information

        Returns:
            list: alerts that were generated from this test event
        """
        event = {'Records': [formatted_record]}
        # Run tests on the formatted record
        alerts, expected_alerts, all_records_matched_schema = self.test_rule(
            rule_name,
            test_record,
            event)

        alerted_properly = (len(alerts) == expected_alerts)
        current_test_passed = alerted_properly and all_records_matched_schema

        self.all_tests_passed = current_test_passed and self.all_tests_passed

        # Print rule name for section header, but only if we get
        # to a point where there is a record to actually be tested.
        # This avoids potentialy blank sections
        if print_header_line and (alerts or self.print_output):
            print '\n{}'.format(rule_name)

        if self.print_output:
            report_output(current_test_passed, [
                '[trigger={}]'.format(expected_alerts),
                'rule',
                test_record['service'],
                test_record['description']])

        # Add the status of the rule to messages list
        if not all_records_matched_schema:
            self.analyze_record_delta(rule_name, test_record)
        elif not alerted_properly:
            message = 'Rule failure: {}'.format(test_record['description'])
            self.status_messages.append(StatusMessage(StatusMessage.FAILURE, rule_name, message))

        # Return the alerts back to caller
        return alerts

    def _get_rule_test_files(self, filter_rules, validate_only):
        """Helper to get rule files to be tested

        Args:
            filter_rules (list|None): List of specific rule names or file names
                (or None) that has been fed in from the CLI to restrict testing to

        Yields:
            str: rule name
            dict: loaded json contents of the respective test event file
        """
        # Since filter_rules can be either a list of rule names or rule files,
        # we should check to see if there is a '.json' extension and just use the
        # base filename. This approach avoids two functions that do largely the same thing
        if filter_rules:
            for index, rule in enumerate(filter_rules):
                parts = os.path.splitext(rule)
                if parts[1] == '.json':
                    filter_rules[index] = parts[0]

            # Create a copy of the filtered rules that can be altered
            filter_rules_copy = filter_rules[:]

        for _, _, test_rule_files in os.walk(DIR_RULES):
            for rule_file in test_rule_files:
                rule_name = os.path.splitext(rule_file)[0]

                # If only specific rules are being tested,
                # skip files that do not match those rules
                if filter_rules:
                    if rule_name not in filter_rules:
                        continue

                    filter_rules_copy.remove(rule_name)

                with open(os.path.join(DIR_RULES, rule_file), 'r') as rule_file_handle:
                    try:
                        contents = json.load(rule_file_handle)
                    except (ValueError, TypeError) as err:
                        self.all_tests_passed = False
                        message = 'Improperly formatted file ({}): {}'.format(
                            rule_file, err.message)
                        self.status_messages.append(
                            StatusMessage(StatusMessage.WARNING, rule_name, message))
                        continue

                if not contents.get('records'):
                    self.all_tests_passed = False
                    self.status_messages.append(
                        StatusMessage(
                            StatusMessage.WARNING,
                            rule_name,
                            'No records to test in file'))
                    continue

                yield rule_name, contents

        # Print any of the filtered rules that remain in the list
        # This means that there are not tests configured for them
        if filter_rules and filter_rules_copy:
            self.all_tests_passed = False
            message = 'No test events configured for designated rule'
            for filter_rule in filter_rules:
                if validate_only:
                    message = 'Designated file ({}.json) does not exist within \'{}\''.format(
                        filter_rule, DIR_RULES)
                self.status_messages.append(
                    StatusMessage(StatusMessage.WARNING, filter_rule, message))

    def check_keys(self, rule_name, test_record):
        """Check the test_record contains the required keys

        Args:
            rule_name (str): The name of the rule being tested. This is passed in
                here strictly for reporting any errors with key checks.
            test_record (dict): The raw test record being processed

        Returns:
            bool: True if the proper keys are present
        """
        required_keys = {'data', 'description', 'service', 'source', 'trigger'}

        record_keys = set(test_record.keys())
        if not required_keys.issubset(record_keys):
            req_key_diff = required_keys.difference(record_keys)
            missing_keys = ','.join('\'{}\''.format(key) for key in req_key_diff)
            message = 'Missing required key(s) in log: {}'.format(missing_keys)
            self.status_messages.append(StatusMessage(StatusMessage.FAILURE, rule_name, message))
            return False

        optional_keys = {'trigger_count', 'compress'}

        key_diff = record_keys.difference(required_keys | optional_keys)

        # Log a warning if there are extra keys declared in the test log
        if key_diff:
            extra_keys = ','.join('\'{}\''.format(key) for key in key_diff)
            message = 'Additional unnecessary keys in log: {}'.format(extra_keys)
            # Remove the key(s) and just warn the user that they are extra
            record_keys.difference_update(key_diff)
            self.status_messages.append(
                StatusMessage(StatusMessage.WARNING, rule_name, message)
            )

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
            test_record (dict): loaded fixture file JSON as a dict.
        """
        # declare all helper functions here, they should always return a string
        record_helpers = {
            'last_hour': lambda: str(int(time.time()) - 60)
        }
        helper_regex = re.compile(r'<helper:(?P<helper>\w+)>')

        def find_and_apply_helpers(test_record):
            """Apply any helpers to the passed in test_record"""
            for key, value in test_record.iteritems():
                if isinstance(value, (str, unicode)):
                    test_record[key] = re.sub(
                        helper_regex,
                        lambda match: record_helpers[match.group('helper')](),
                        test_record[key]
                    )
                elif isinstance(value, dict):
                    find_and_apply_helpers(test_record[key])

        find_and_apply_helpers(test_record)

    def report_output_summary(self):
        """Helper function to print the summary results of all tests"""
        failure_messages = [
            item for item in self.status_messages if item.type == StatusMessage.FAILURE]
        warning_messages = [
            item for item in self.status_messages if item.type == StatusMessage.WARNING]
        passed_tests = sum(
            1 for item in self.status_messages if item.type == StatusMessage.SUCCESS)
        passed_tests = self.total_tests - len(failure_messages)
        # Print some lines at the bottom of output to make it more readable
        # This occurs here so there is always space and not only when the
        # successful test info prints
        print '\n\n'

        # Only print success info if we explicitly want to print output
        # but always print any errors or warnings below
        if self.print_output:
            # Print a message indicating how many of the total tests passed
            LOGGER_CLI.info('%s(%d/%d) Successful Tests%s', COLOR_GREEN, passed_tests,
                            self.total_tests, COLOR_RESET)

        # Check if there were failed tests and report on them appropriately
        if failure_messages:
            # Print a message indicating how many of the total tests failed
            LOGGER_CLI.error('%s(%d/%d) Failures%s', COLOR_RED, len(failure_messages),
                             self.total_tests, COLOR_RESET)

            # Iterate over the rule_name values in the failed list and report on them
            for index, failure in enumerate(failure_messages, start=1):
                LOGGER_CLI.error('%s(%d/%d) [%s] %s%s', COLOR_RED, index,
                                 len(failure_messages), failure.rule, failure.message,
                                 COLOR_RESET)

        # Check if there were any warnings and report on them
        if warning_messages:
            warning_count = len(warning_messages)
            LOGGER_CLI.warn('%s%d Warning%s%s', COLOR_YELLOW, warning_count,
                            ('s' if warning_count > 1 else ''), COLOR_RESET)

            for index, warning in enumerate(warning_messages, start=1):
                LOGGER_CLI.warn('%s(%d/%d) [%s] %s%s', COLOR_YELLOW, index, warning_count,
                                warning.rule, warning.message, COLOR_RESET)

    def test_rule(self, rule_name, test_record, event):
        """Feed formatted records into StreamAlert and check for alerts

        Args:
            rule_name (str): The rule name being tested
            test_record (dict): A single raw record to test
            event (dict): A formatted event that reflects the structure expected
                as input to the Lambda function.

        Returns:
            list: alerts that hit for this rule
            int: count of expected alerts for this rule
            bool: False if errors occurred during processing
        """
        # Clear out any old alerts or errors from the previous test run
        # pylint: disable=protected-access
        del self.processor._alerts[:]
        self.processor._failed_record_count = 0

        expected_alert_count = test_record.get('trigger_count')
        if not expected_alert_count:
            expected_alert_count = 1 if test_record['trigger'] else 0

        # Run the rule processor
        all_records_matched_schema = self.processor.run(event)

        alerts = self.processor.get_alerts()

        # we only want alerts for the specific rule being tested
        alerts = [alert for alert in alerts
                  if alert['rule_name'] == rule_name]

        return alerts, expected_alert_count, all_records_matched_schema

    def analyze_record_delta(self, rule_name, test_record):
        """Provide some additional context on why this test failed. This will
        perform some analysis of the test record to determine which keys are
        missing or which unnecessary keys are causing the test to fail. Any
        errors are appended to a list of errors so they can be printed at
        the end of the test run.

        Args:
            rule_name (str): Name of rule being tested
            test_record (dict): Actual record data being tested
        """
        logs = self.processor.classifier.get_log_info_for_source()
        rule_info = StreamRules.get_rules()[rule_name]
        test_record_keys = set(test_record['data'])
        for log in rule_info.logs:
            if log not in logs:
                message = 'Log declared in rule ({}) does not exist in logs.json'.format(
                    log)
                self.status_messages.append(
                    StatusMessage(StatusMessage.FAILURE, rule_name, message))
                continue
            all_record_schema_keys = set(logs[log]['schema'])
            optional_keys = set(logs[log].get('configuration',
                                              {}).get('optional_top_level_keys', {}))

            min_req_record_schema_keys = all_record_schema_keys.difference(optional_keys)

            schema_diff = min_req_record_schema_keys.difference(test_record_keys)
            if schema_diff:
                message = ('Data is invalid due to missing key(s) in test record: {}. '
                           'Rule: \'{}\'. Description: \'{}\''.format(
                               ', '.join('\'{}\''.format(key) for key in schema_diff),
                               rule_info.rule_name,
                               test_record['description']))

                self.status_messages.append(
                    StatusMessage(StatusMessage.FAILURE, rule_name, message))
                continue

            unexpected_record_keys = test_record_keys.difference(all_record_schema_keys)
            if unexpected_record_keys:
                message = (
                    'Data is invalid due to unexpected key(s) in test record: {}. '
                    'Rule: \'{}\'. Description: \'{}\''.format(
                        ', '.join(
                            '\'{}\''.format(key) for key in unexpected_record_keys),
                        rule_info.rule_name,
                        test_record['description']))

                self.status_messages.append(
                    StatusMessage(StatusMessage.FAILURE, rule_name, message))


class AlertProcessorTester(object):
    """Class to encapsulate testing the alert processor"""
    _alert_fail_pass = [0, 0]

    def __init__(self, context):
        """AlertProcessorTester initializer

        Args:
            context (namedtuple): Constructed aws context object. The
                namedtuple contains an attribute of `mocked` that indicates
                if all dispatch calls should be mocked out instead of actually
                performed. If not mocked, the tests will attempt to actually
                send alerts to outputs.
        """
        self.all_tests_passed = True
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
            alerts (list): list of alerts to be processed that have been fed in
                from the rule processor.

        Return:
            bool: status of the alert processor dispatching
        """
        # Set the logger level to info so its not too noisy
        StreamOutput.LOGGER.setLevel(logging.ERROR)
        for alert in alerts:
            if self.context.mocked:
                self.setup_outputs(alert)

            for current_test_passed, output in StreamOutput.handler(alert, self.context):
                self.all_tests_passed = current_test_passed and self.all_tests_passed
                service, descriptor = output.split(':')
                message = 'sending alert to \'{}\''.format(descriptor)
                report_output(current_test_passed, [
                    '',
                    'alert',
                    service,
                    message
                ])

                self._alert_fail_pass[current_test_passed] += 1

    @classmethod
    def report_output_summary(cls):
        """Helper function to print the summary results of all alert tests"""
        failed_tests = cls._alert_fail_pass[0]
        passed_tests = cls._alert_fail_pass[1]
        total_tests = failed_tests + passed_tests

        # Print a message indicating how many of the total tests passed
        LOGGER_CLI.info('%s(%d/%d) Alert Tests Passed%s', COLOR_GREEN,
                        passed_tests, total_tests, COLOR_RESET)

        # Check if there were failed tests and report on them appropriately
        if failed_tests:
            # Print a message indicating how many of the total tests failed
            LOGGER_CLI.error('%s(%d/%d) Alert Tests Failed%s', COLOR_RED,
                             failed_tests, total_tests, COLOR_RESET)

    def setup_outputs(self, alert):
        """Helper function to handler any output setup

        Args:
            alert (dict): The alert dictionary containing outputs the need mocking out
        """
        outputs = alert.get('outputs', [])
        # Patch the urllib2.urlopen event to override HTTPStatusCode, etc
        url_mock = Mock()
        patch('urllib2.urlopen', url_mock).start()
        for output in outputs:
            try:
                service, descriptor = output.split(':')
            except ValueError:
                LOGGER_CLI.error('Outputs should be declared in the format <SERVICE>:<DESCRIPTOR>')
                continue

            if service == 'aws-s3':
                bucket = self.outputs_config[service][descriptor]
                boto3.client('s3', region_name='us-east-1').create_bucket(Bucket=bucket)
            elif service == 'aws-lambda':
                lambda_function = self.outputs_config[service][descriptor]
                parts = lambda_function.split(':')
                if len(parts) == 2 or len(parts) == 8:
                    lambda_function = parts[-2]
                else:
                    lambda_function = parts[-1]
                helpers.create_lambda_function(lambda_function, 'us-east-1')
            elif service == 'pagerduty':
                output_name = '{}/{}'.format(service, descriptor)
                creds = {'service_key': '247b97499078a015cc6c586bc0a92de6'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       'us-east-1', self.kms_alias)

                # Set the patched urlopen.getcode return value to 200
                url_mock.return_value.getcode.return_value = 200
            elif service == 'phantom':
                output_name = '{}/{}'.format(service, descriptor)
                creds = {'ph_auth_token': '6c586bc047b9749a92de29078a015cc6',
                         'url': 'phantom.foo.bar'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       'us-east-1', self.kms_alias)

                # Set the patched urlopen.getcode return value to 200
                url_mock.return_value.getcode.return_value = 200
                # Phantom needs a container 'id' value in the http response
                url_mock.return_value.read.return_value = '{"id": 1948}'
            elif service == 'slack':
                output_name = '{}/{}'.format(service, descriptor)
                creds = {'url': 'https://api.slack.com/web-hook-key'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       'us-east-1', self.kms_alias)

                # Set the patched urlopen.getcode return value to 200
                url_mock.return_value.getcode.return_value = 200


def report_output(passed, cols):
    """Helper function to pretty print columns for reporting results

    Args:
        passed (bool): The pass status of the current test case
        cols (list): A list of columns to print as output
    """

    status = ('{}[Pass]{}'.format(COLOR_GREEN, COLOR_RESET) if passed else
              '{}[Fail]{}'.format(COLOR_RED, COLOR_RESET))

    print '{:>26}  {:<28}  {:<8}  ({}): {}'.format(status, *cols)


def check_untested_rules():
    """Function that prints warning log messages for rules that exist but do
    not have proper integration tests configured.
    """
    all_test_files = {os.path.splitext(test_file)[0] for _, _, test_rule_files
                      in os.walk(DIR_RULES) for test_file in test_rule_files}

    untested_rules = set(StreamRules.get_rules()).difference(all_test_files)

    for rule in untested_rules:
        LOGGER_CLI.warn('%sNo tests configured for rule: \'%s\'. Please add a '
                        'corresponding test file for this rule in \'%s\' with the '
                        'name \'%s.json\' to avoid seeing this warning%s', COLOR_YELLOW,
                        rule, DIR_RULES, rule, COLOR_RESET)


def check_untested_files():
    """Function that prints warning log messages for integration test files
    that exist but do not have a corresponding rule configured.
    """
    all_test_files = {os.path.splitext(test_file)[0] for _, _, test_rule_files
                      in os.walk(DIR_RULES) for test_file in test_rule_files}

    untested_rules = all_test_files.difference(set(StreamRules.get_rules()))

    for rule in untested_rules:
        LOGGER_CLI.warn('%sNo rules configured for test file: \'%s.json\'. Please '
                        'add a corresponding rule for this test file in \'rules/\' with '
                        'the name \'%s.py\' to avoid seeing this warning and any associated '
                        'errors above%s', COLOR_YELLOW,
                        rule, rule, COLOR_RESET)


def stream_alert_test(options, config=None):
    """High level function to wrap the integration testing entry point.
    This encapsulates the testing function and is used to specify if calls
    should be mocked.

    Args:
        options (namedtuple): CLI options (debug, processor, etc)
        config (CLIConfig): Configuration for this StreamAlert setup that
            includes cluster info, etc that can be used for constructing
            an aws context object
    """
    # get the options in a dictionary so we can do easy lookups
    run_options = vars(options)
    context = helpers.get_context_from_config(run_options.get('cluster'), config)

    @helpers.mock_me(context)
    def run_tests(options, context):
        """Actual protected function for running tests

        Args:
            options (namedtuple): CLI options (debug, processor, etc)
            context (namedtuple): A constructed aws context object
        """
        if options.debug:
            # TODO(jack): Currently there is no (clean) way to set
            #             the logger formatter to provide more verbose
            #             output in debug mode.  Running basicConfig twice
            #             does not actually change the formatter on the logger object.
            #             This functionality can be added during the logging refactor
            # Example Steps:
            #   call .shutdown() on the existing logger
            #   debug_formatter = logging.Formatter(
            #       '%(name)s [%(levelname)s]: [%(module)s.%(funcName)s] %(message)s')
            #   set the new logger to the formatter above
            for streamalert_logger in (LOGGER_SA, LOGGER_SH, LOGGER_SO, LOGGER_CLI):
                streamalert_logger.setLevel(logging.DEBUG)
        else:
            # Add a filter to suppress a few noisy log messages
            LOGGER_SA.addFilter(SuppressNoise())

        # Create an in memory logging buffer to be used to caching all error messages
        log_mem_hanlder = get_log_memory_hanlder()

        # Check if the rule processor should be run for these tests
        test_rules = (set(run_options.get('processor')).issubset({'rule', 'all'})
                      if run_options.get('processor') else
                      run_options.get('command') == 'live-test' or
                      run_options.get('command') == 'validate-schemas')

        # Check if the alert processor should be run for these tests
        test_alerts = (set(run_options.get('processor')).issubset({'alert', 'all'})
                       if run_options.get('processor') else
                       run_options.get('command') == 'live-test')

        rule_proc_tester = RuleProcessorTester(context, test_rules)
        alert_proc_tester = AlertProcessorTester(context)

        validate_schemas = options.command == 'validate-schemas'

        filters = options.test_files if validate_schemas else options.rules

        # Run the rule processor for all rules or designated rule set
        for alerts in rule_proc_tester.test_processor(filters, validate_schemas):
            # If the alert processor should be tested, process any alerts
            if test_alerts:
                alert_proc_tester.test_processor(alerts)

        # Report summary information for the alert processor if it was ran
        if test_alerts:
            AlertProcessorTester.report_output_summary()

        # Check all of the rule files to make sure they have tests configured
        check_untested_rules()

        # If this is not just a validation run, then warn the user
        # if there are test files without corresponding rules
        if not validate_schemas:
            check_untested_files()

        if not (rule_proc_tester.all_tests_passed and
                alert_proc_tester.all_tests_passed):
            sys.exit(1)

        # If there are any log records in the memory buffer, then errors occured somewhere
        if log_mem_hanlder.buffer:
            # Release the MemoryHandler so we can do some other logging now
            logging.getLogger().removeHandler(log_mem_hanlder)
            LOGGER_CLI.error('%sSee %d miscellaneous error(s) below '
                             'that were encountered and may need to be addressed%s',
                             COLOR_RED, len(log_mem_hanlder.buffer), COLOR_RESET)

            log_mem_hanlder.setTarget(LOGGER_CLI)
            log_mem_hanlder.flush()

            sys.exit(1)

    run_tests(options, context)

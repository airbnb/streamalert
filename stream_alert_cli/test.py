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
# pylint: disable=too-many-lines,too-many-statements
from collections import namedtuple
import logging
import os
import re
import shutil
import sys
import tempfile
import time

import boto3
from botocore.exceptions import ClientError
import jsonpath_rw
from mock import patch

from stream_alert.alert_processor import main as StreamOutput
from stream_alert.alert_processor.outputs import carbonblack
from stream_alert.rule_processor.handler import StreamAlert
from stream_alert.rule_processor.parsers import get_parser
from stream_alert.rule_processor.payload import load_stream_payload
from stream_alert.shared import resources, stats, rule
from stream_alert_cli import helpers
from stream_alert_cli.logger import (
    get_log_memory_handler,
    LOGGER_CLI,
    LOGGER_SA,
    SuppressNoise
)


TEST_EVENTS_DIR = 'tests/integration/rules'
COLOR_RED = '\033[0;31;1m'
COLOR_YELLOW = '\033[0;33;1m'
COLOR_GREEN = '\033[0;32;1m'
COLOR_RESET = '\033[0m'


StatusMessageBase = namedtuple('StatusMessage', 'type, message')


class StatusMessage(StatusMessageBase):
    """Simple class to encapsulate a status message"""
    WARNING = -1
    SUCCESS = 0
    FAILURE = 1


class RuleProcessorTester(object):
    """Class to encapsulate testing the rule processor"""

    def __init__(self, context, config, print_output):
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
        self.processor = StreamAlert(context)
        self.cli_config = config
        # Use a list of status_messages to store pass/fail/warning info
        self.status_messages = []
        self.total_tests = 0
        self.all_tests_passed = True
        self.print_output = print_output
        # Configure mocks for Firehose and DDB
        helpers.setup_mock_firehose_delivery_streams(config)
        helpers.setup_mock_dynamodb_ioc_table(config)
        # Create a cache map of parsers to parser classes
        self.parsers = {}

        # Patch the tmp shredding as to not slow down testing
        patch('stream_alert.rule_processor.payload.S3Payload._shred_temp_directory').start()

        # Patch random_bool to always return true
        patch('helpers.base.random_bool', return_value=True).start()

    def test_processor(self, rules_filter, files_filter, validate_only):
        """Perform integration tests for the 'rule' Lambda function

        Args:
            rules_filter (set): A collection of rules to filter on, passed in by the user
                via the CLI using the --test-rules option.
            files_filter (set): A collection of files to filter on, passed in by the user
                via the CLI using the --test-files option.
            validate_only (bool): If true, validation of test records will occur
                without the rules engine being applied to events.

        Yields:
            tuple (bool, list) or None: If testing rules, this yields a tuple containig a
                boolean of test status and a list of alerts to run through the alert
                processor. If validating test records only, this does not yield.
        """
        test_file_info = self._filter_files(
            helpers.get_rule_test_files(TEST_EVENTS_DIR),
            files_filter
        )

        for name in sorted(test_file_info):
            path = test_file_info[name]

            events, error = helpers.load_test_file(path)
            if error is not None:
                self.all_tests_passed = False
                self.status_messages.append(StatusMessage(StatusMessage.WARNING, error))
                continue

            print_header = True
            for test_event in events:
                self.total_tests += 1
                if self._detect_old_test_event(test_event):
                    self.all_tests_passed = False
                    message = ('Detected old format for test event in file \'{}.json\'. '
                               'Please visit https://streamalert.io/rule-testing.html '
                               'for information on the new format and update your '
                               'test events accordingly.'.format(name))
                    self.status_messages.append(StatusMessage(StatusMessage.FAILURE, message))
                    continue

                if not self.check_keys(test_event):
                    self.all_tests_passed = False
                    continue

                # Check if there are any rule filters in place, and if the current test event
                # should be exeecuted per the filter
                if rules_filter and set(test_event['trigger_rules']).isdisjoint(rules_filter):
                    self.total_tests -= 1
                    continue

                self.apply_helpers(test_event)

                if 'override_record' in test_event:
                    self.apply_template(test_event)

                formatted_record = helpers.format_lambda_test_record(test_event)

                # If this test is to validate the schema only, continue the loop and
                # do not yield results on the rule tests below
                if validate_only or (not validate_only and test_event.get('validate_schema_only')):
                    if self._validate_test_record(name, test_event, formatted_record,
                                                  print_header) is False:
                        self.all_tests_passed = False
                else:
                    yield self._run_rule_tests(name, test_event, formatted_record, print_header)

                print_header = False

        # Report on the final test results
        self.report_output_summary()

    def _filter_files(self, file_info, files_filter):
        """Filter the test files based in input from the user

        Args:
            file_info (dict): Information about test files on disk, where the key is the
                base name of the file and the value is the relative path to the file
            files_filter (set): A collection of files to filter tests on

        Returns:
            dict: A modified version of the `file_info` arg with pared down values
        """
        if not files_filter:
            return file_info

        files_filter = {os.path.splitext(name)[0] for name in files_filter}

        file_info = {name: path for name, path in file_info.iteritems()
                     if os.path.splitext(name)[0] in files_filter}

        filter_diff = set(files_filter).difference(set(file_info))
        message_template = 'No test events file found with base name \'{}\''
        for missing_file in filter_diff:
            self.status_messages.append(
                StatusMessage(StatusMessage.WARNING, message_template.format(missing_file)))

        return file_info

    def _validate_test_record(self, file_name, test_event, formatted_record, print_header_line):
        """Function to validate test records and log any errors

        Args:
            file_name (str): The base name of the test event file.
            test_event (dict): A single test event containing the record and other detail
            formatted_record (dict): A dictionary that includes the 'data' from the
                test record, formatted into a structure that is resemblant of how
                an incoming record from a service would format it.
                See test/integration/templates for example of how each service
                formats records.
            print_header_line (bool): Indicates if this is the first record from
                a test file, and therefore we should print some header information
        """
        service, entity = self.processor.classifier.extract_service_and_entity(formatted_record)

        if not self.processor.classifier.load_sources(service, entity):
            return False

        # Create the StreamPayload to use for encapsulating parsed info
        payload = load_stream_payload(service, entity, formatted_record)
        if not payload:
            return False

        if print_header_line:
            print '\n{}'.format(file_name)

        for record in payload.pre_parse():
            self.processor.classifier.classify_record(record)

            if not record.valid:
                self.all_tests_passed = False
                self.analyze_record_delta(file_name, test_event)

            report_output(record.valid, [
                '[log=\'{}\']'.format(record.log_source or 'unknown'),
                'validation',
                record.service(),
                test_event['description']])

    def _run_rule_tests(self, file_name, test_event, formatted_record, print_header_line):
        """Run tests on a test record for a given rule

        Args:
            file_name (str): The base name of the test event file.
            test_event (dict): The loaded test event from json
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

        expected_alert_count = len(test_event['trigger_rules'])

        # Run tests on the formatted record
        alerts, all_records_matched_schema = self.test_rule(event)

        # Get a list of any rules that triggerer but are not defined in the 'trigger_rules'
        unexpected_alerts = []

        disabled_rules = [item for item in test_event['trigger_rules']
                          if rule.Rule.get_rule(item).disabled]

        expected_alert_count -= len(disabled_rules)

        triggers = set(test_event['trigger_rules']) - set(disabled_rules)
        # we only want alerts for the specific rule being tested (if trigger_rules are defined)
        if triggers:
            unexpected_alerts = [alert for alert in alerts
                                 if alert.rule_name not in triggers]

            alerts = [alert for alert in alerts
                      if alert.rule_name in triggers]

        alerted_properly = (len(alerts) == expected_alert_count) and not unexpected_alerts
        current_test_passed = alerted_properly and all_records_matched_schema

        self.all_tests_passed = current_test_passed and self.all_tests_passed

        # Print rule name for section header, but only if we get
        # to a point where there is a record to actually be tested.
        # This avoids potentially blank sections
        if print_header_line and (alerts or self.print_output):
            print '\n{}'.format(file_name)

        if self.print_output:
            disabled_output = ''
            if disabled_rules:
                disabled_output = ',disabled={}'.format(len(disabled_rules))
            report_output(current_test_passed, [
                '[trigger={}{}]'.format(expected_alert_count, disabled_output),
                'rule',
                test_event['service'],
                test_event['description']])

        # Add the status of the rule to messages list
        if not all_records_matched_schema:
            self.analyze_record_delta(file_name, test_event)
        elif not alerted_properly:
            message = ('Test failure: [{}.json] Test event with description '
                       '\'{}\'').format(file_name, test_event['description'])
            if alerts and not triggers:
                # If there was a failure due to alerts triggering for a test event
                # that does not have any trigger_rules configured
                context = 'is triggering the following rules but should not trigger at all: {}'
                trigger_rules = ', '.join('\'{}\''.format(alert.rule_name) for alert in alerts)
                message = '{} {}'.format(message, context.format(trigger_rules))
            elif unexpected_alerts:
                # If there was a failure due to alerts triggering for other rules outside
                # of the rules defined in the trigger_rules list for the event
                context = 'is triggering the following rules but should not be: {}'
                bad_rules = ', '.join(
                    '\'{}\''.format(alert.rule_name) for alert in unexpected_alerts)
                message = '{} {}'.format(message, context.format(bad_rules))
            elif expected_alert_count != len(alerts):
                # If there was a failure due to alerts NOT triggering for 1+ rules
                # defined in the trigger_rules list for the event
                context = 'did not trigger the following rules: {}'
                non_triggered_rules = ', '.join(
                    '\'{}\''.format(rule) for rule in triggers
                    if rule not in [alert.rule_name for alert in alerts])
                message = '{} {}'.format(message, context.format(non_triggered_rules))
            else:
                # If there was a failure for some other reason, just use a default message
                message = 'Rule failure: [{}.json] {}'.format(file_name, test_event['description'])
            self.status_messages.append(StatusMessage(StatusMessage.FAILURE, message))

        # Return the alerts back to caller
        return alerts

    @staticmethod
    def _detect_old_test_event(test_event):
        """Check if the test event contains the old format used

        Args:
            test_event (dict): The loaded test event from json

        Returns:
            bool: True if a legacy test file is detected, False otherwise
        """
        record_keys = set(test_event)
        if (not {'log', 'trigger_rules'}.issubset(record_keys) and
                {'trigger'}.issubset(record_keys)):
            return True

        return False

    def check_keys(self, test_event):
        """Check if the test event contains the required keys

        Args:
            test_event (dict): The loaded test event from json

        Returns:
            bool: True if the proper keys are present
        """
        required_keys = {'description', 'log', 'service', 'source', 'trigger_rules'}

        record_keys = set(test_event)
        if not required_keys.issubset(record_keys):
            req_key_diff = required_keys.difference(record_keys)
            missing_keys = ', '.join('\'{}\''.format(key) for key in req_key_diff)
            message = 'Missing required key(s) in log: {}'.format(missing_keys)
            self.status_messages.append(StatusMessage(StatusMessage.FAILURE, message))
            return False

        input_data_keys = {'data', 'override_record'}
        if not record_keys & input_data_keys:
            missing_keys = ', '.join('\'{}\''.format(key) for key in input_data_keys)
            message = 'Missing one of the following keys in log: {}'.format(missing_keys)
            self.status_messages.append(StatusMessage(StatusMessage.FAILURE, message))
            return False

        optional_keys = {'compress', 'validate_schema_only'}

        key_diff = record_keys.difference(required_keys | optional_keys | input_data_keys)

        # Log a warning if there are extra keys declared in the test log
        if key_diff:
            extra_keys = ', '.join('\'{}\''.format(key) for key in key_diff)
            message = 'Additional unnecessary keys in log: {}'.format(extra_keys)
            # Remove the key(s) and just warn the user that they are extra
            record_keys.difference_update(key_diff)
            self.status_messages.append(StatusMessage(StatusMessage.WARNING, message))

        return record_keys.issubset(required_keys | optional_keys | input_data_keys)

    def apply_template(self, test_event):
        """Apply default values to the given test event

        Args:
            test_event (dict): The loaded test event
        """
        event_log = self.cli_config['logs'].get(test_event['log'])

        parser = event_log['parser']
        schema = event_log['schema']
        configuration = event_log.get('configuration', {})

        # Add envelope keys
        schema.update(configuration.get('envelope_keys', {}))

        # Setup the parser to access default optional values
        self.parsers[parser] = self.parsers.get(parser, get_parser(parser))

        # Add apply default values based on the declared schema
        default_test_event = {key: self.parsers[parser].default_optional_values(value)
                              for key, value
                              in schema.iteritems()}

        # Fill in the fields left out in the 'override_record' field,
        # and update the test event with a full 'data' key
        default_test_event.update(test_event['override_record'])
        test_event['data'] = default_test_event

    @staticmethod
    def apply_helpers(test_record):
        """Detect and apply helper functions to test event data

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
                LOGGER_CLI.error('%s(%d/%d) %s%s', COLOR_RED, index,
                                 len(failure_messages), failure.message, COLOR_RESET)

        # Check if there were any warnings and report on them
        if warning_messages:
            warning_count = len(warning_messages)
            LOGGER_CLI.warn('%s%d Warning%s%s', COLOR_YELLOW, warning_count,
                            ('s' if warning_count > 1 else ''), COLOR_RESET)

            for index, warning in enumerate(warning_messages, start=1):
                LOGGER_CLI.warn('%s(%d/%d) %s%s', COLOR_YELLOW, index, warning_count,
                                warning.message, COLOR_RESET)

    def test_rule(self, record):
        """Feed formatted records into StreamAlert and check for alerts

        Args:
            record (dict): A formatted event that reflects the structure expected
                as input to the Lambda function.

        Returns:
            list: alerts that hit for this rule
            bool: False if errors occurred during processing
        """
        # Clear out any old alerts or errors from the previous test run
        # pylint: disable=protected-access
        del self.processor._alerts[:]
        self.processor._failed_record_count = 0

        # Run the rule processor
        all_records_matched_schema = self.processor.run(record)

        return self.processor.alerts, all_records_matched_schema

    def check_log_declared_in_sources(self, base_message, test_event):
        """A simple check to see if this log type is defined in the sources for the service

        Args:
            base_message (str): Base error message to be reported with extra context
            test_event (dict): Actual record data being tested

        Returns:
            bool: False if the log type is not in the sources list, True if it is
        """
        source = test_event['source']
        service = test_event['service']
        log = test_event['log'].split(':')[0]
        if not log in self.cli_config['sources'][service][source]['logs']:
            message = ('The \'sources.json\' file does not include the log type \'{}\' '
                       'in the list of logs for this service & entity (\'{}:{}\').')
            message = '{} {}'.format(base_message, message.format(log, service, source))
            self.status_messages.append(StatusMessage(StatusMessage.FAILURE, message))
            return False

        return True

    def analyze_record_delta(self, file_name, test_event):
        """Provide some additional context on why this test failed. This will
        perform some analysis of the test record to determine which keys are
        missing or which unnecessary keys are causing the test to fail. Any
        errors are appended to a list of errors so they can be printed at
        the end of the test run.

        Args:
            file_name (str): Name of file containing the test event
            test_event (dict): Actual record data being tested
        """
        base_message = ('Invalid test event in file \'{}.json\' with description '
                        '\'{}\'.'.format(file_name, test_event['description']))

        if not self.check_log_declared_in_sources(base_message, test_event):
            return

        log_type = test_event['log']
        if log_type not in self.cli_config['logs']:
            message = ('{} Log (\'{}\') declared in test event does not exist in '
                       'logs.json'.format(base_message, log_type))

            self.status_messages.append(StatusMessage(StatusMessage.FAILURE, message))
            return

        config_log_info = self.cli_config['logs'][log_type]
        schema_keys = config_log_info['schema']

        envelope_keys = config_log_info.get('configuration', {}).get('envelope_keys')
        if envelope_keys:
            if self.report_envelope_key_error(base_message, envelope_keys, test_event['data']):
                return

        # Check is a json path is used for nested records
        json_path = config_log_info.get('configuration', {}).get('json_path')
        if json_path:
            records_jsonpath = jsonpath_rw.parse(json_path)
            for match in records_jsonpath.find(test_event['data']):
                self.report_record_delta(base_message, log_type, schema_keys, match.value)

            return

        self.report_record_delta(base_message, log_type, schema_keys, test_event['data'])

    def report_envelope_key_error(self, base_message, envelope_keys, test_record):
        """Provide context failures related to envelope key issues.

        Args:
            base_message (str): Base error message to be reported with extra context
            envelope_keys (list): A collection of the envelope keys for this nested schema
            test_record (dict): Actual record being tested - this could be one of
                many records extracted using jsonpath_rw
        """
        missing_env_key_list = set(envelope_keys).difference(set(test_record))
        if missing_env_key_list:
            missing_key_list = ', '.join('\'{}\''.format(key) for key in missing_env_key_list)
            message = ('{} Data is invalid due to missing envelope key(s) in test record: '
                       '{}.'.format(base_message, missing_key_list))

            self.status_messages.append(StatusMessage(StatusMessage.FAILURE, message))
            return True

        return False

    def report_record_delta(self, base_message, log_type, schema_keys, test_record):
        """Provide context on why this specific record failed.

        Args:
            base_message (str): Base error message to be reported with extra context
            log_type (str): Type of log being tested
            schema_keys (set): A collection of the keys from the schema
            test_record (dict): Actual record being tested - this could be one of
                many records extracted using jsonpath_rw
        """
        optional_keys = set(
            self.cli_config['logs'] \
                [log_type].get('configuration', {}).get('optional_top_level_keys', {})
        )

        min_req_record_schema_keys = set(schema_keys).difference(optional_keys)

        test_record_keys = set(test_record)

        schema_diff = min_req_record_schema_keys.difference(test_record_keys)
        if schema_diff:
            missing_key_list = ', '.join('\'{}\''.format(key) for key in schema_diff)
            message = ('{} Data is invalid due to missing key(s) in test record: '
                       '{}.'.format(base_message, missing_key_list))

            self.status_messages.append(StatusMessage(StatusMessage.FAILURE, message))
            return

        unexpected_keys = test_record_keys.difference(schema_keys)
        if unexpected_keys:
            unexpected_key_list = ', '.join('\'{}\''.format(key) for key in unexpected_keys)
            message = ('{} Data is invalid due to unexpected key(s) in test record: '
                       '{}.'.format(base_message, unexpected_key_list))

            self.status_messages.append(StatusMessage(StatusMessage.FAILURE, message))
            return

        # Add a generic error message if we can not determine what the issue is
        message = '{} Please look for any errors above.'.format(base_message)
        self.status_messages.append(StatusMessage(StatusMessage.FAILURE, message))


class AlertProcessorTester(object):
    """Class to encapsulate testing the alert processor"""
    _alert_fail_pass = [0, 0]

    def __init__(self, config, context):
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
        self.outputs_config = resources.merge_required_outputs(
            config['outputs'],
            'test-prefix'
        )
        self.region = config['global']['account']['region']
        self._cleanup_old_secrets()
        helpers.setup_mock_firehose_delivery_streams(config)

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

            # Convert alert to the Dynamo event format expected by the alert processor
            event = alert.dynamo_record()
            event['Outputs'] = list(event['Outputs'])

            for output, current_test_passed in StreamOutput.handler(event, self.context).items():
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

    @staticmethod
    def _setup_api_mocks():
        """Use some MagicMocks to patch get and post methods for requests

        This uses a dynamic function for the 'side_effect' to for custom responses
        """
        def _mock_side_effect(mocker):

            def _mock_by_service():
                url = mocker.call_args[0][0]
                url_path = os.path.split(url)[1]
                if mocker.method == 'post':
                    if 'jira' in url:
                        if 'auth' in url:
                            return {'session': {'name': 'cookie_name', 'value': 'cookie_value'}}

                        return {'id': 3005}

                    elif 'phantom' in url:
                        return {'id': 1948}

                    elif 'api.pagerduty' in url:
                        if 'incidents' in url_path:
                            return {'incident': {'id': 'incident_id'}}

                    elif 'events.pagerduty' in url:
                        if 'enqueue' in url_path:
                            return {'dedup_key': 'returned_dedup_key'}

                elif mocker.method == 'get':
                    if 'phantom' in 'url':
                        return {'count': 0, 'data': []}

                    elif 'api.pagerduty' in url:
                        return {url_path: [{'id': 1234, 'name': 'foobar'}]}

                # Default to returning an empty dict in case this was not implemented for a service
                return dict()

            return _mock_by_service

        get_patcher = patch('requests.get')
        get_mock = get_patcher.start()
        get_mock.method = 'get'

        # Set the patched request.get return value to 200
        get_mock.return_value.status_code = 200

        # Set the side_effect of the json method to our dynamic function
        # Passing in the get_mock object lets us access the calls to it
        get_mock.return_value.json.side_effect = _mock_side_effect(get_mock)

        post_patcher = patch('requests.post')
        post_mock = post_patcher.start()
        post_mock.method = 'post'

        # Set the patched requests.post return value to 200
        post_mock.return_value.status_code = 200

        # Set the side_effect of the json method to our dynamic function
        # Passing in the post_mock object lets us access the calls to it
        post_mock.return_value.json.side_effect = _mock_side_effect(post_mock)

        put_patcher = patch('requests.put')
        put_mock = put_patcher.start()
        put_mock.method = 'put'

        # Set the patched requests.put return value to 200
        put_mock.return_value.status_code = 200

        cb_patcher = patch.object(carbonblack, 'CbResponseAPI', side_effect=helpers.MockCBAPI)
        cb_patcher.start()

    def setup_outputs(self, alert):
        """Helper function to handler any output setup

        Args:
            alert (Alert): The Alert instance containing outputs to be mocked out
        """
        # Patch requests.get and requests.post
        self._setup_api_mocks()

        alert_outputs = resources.get_required_outputs()
        alert_outputs.update(alert.outputs)

        for output in alert_outputs:
            try:
                service, descriptor = output.split(':')
            except ValueError:
                LOGGER_CLI.error(
                    'Outputs should be declared in the format <SERVICE>:<DESCRIPTOR>')
                continue

            if service == 'aws-s3':
                bucket = self.outputs_config[service][descriptor]
                client = boto3.client('s3', region_name=self.region)
                try:
                    # Check if the bucket exists before creating it
                    client.head_bucket(Bucket=bucket)
                except ClientError:
                    client.create_bucket(Bucket=bucket)

            elif service == 'aws-firehose':
                stream_name = self.outputs_config[service][descriptor]
                helpers.create_delivery_stream(self.region, stream_name)

            elif service == 'aws-lambda':
                lambda_function = self.outputs_config[service][descriptor]
                parts = lambda_function.split(':')
                if len(parts) == 2 or len(parts) == 8:
                    lambda_function = parts[-2]
                else:
                    lambda_function = parts[-1]
                helpers.create_lambda_function(lambda_function,
                                               self.region)

            elif service == 'aws-sns':
                topic_name = self.outputs_config[service][descriptor]
                boto3.client('sns', region_name=self.region).create_topic(Name=topic_name)

            elif service == 'aws-sqs':
                queue_name = self.outputs_config[service][descriptor]
                boto3.client('sqs', region_name=self.region).create_queue(QueueName=queue_name)

            elif service == 'carbonblack':
                output_name = '{}/{}'.format(service, descriptor)
                creds = {'token': 'e51273c7c8e0fd9fae431cc019ab244112345678',
                         'url': 'cb.foo.bar'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       self.region, self.kms_alias)

            elif service == 'komand':
                output_name = '{}/{}'.format(service, descriptor)
                creds = {'komand_auth_token': '00000000-0000-0000-0000-000000000000',
                         'url': 'komand.foo.bar'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       self.region, self.kms_alias)

            elif service == 'pagerduty':
                output_name = '{}/{}'.format(service, descriptor)
                creds = {'service_key': '247b97499078a015cc6c586bc0a92de6'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       self.region, self.kms_alias)

            elif service == 'pagerduty-v2':
                output_name = '{}/{}'.format(service, descriptor)
                creds = {'routing_key': '247b97499078a015cc6c586bc0a92de6'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       self.region, self.kms_alias)

            elif service == 'pagerduty-incident':
                output_name = '{}/{}'.format(service, descriptor)
                creds = {'token': '247b97499078a015cc6c586bc0a92de6',
                         'service_name': '247b97499078a015cc6c586bc0a92de6',
                         'service_id': 'SERVICEID123',
                         'escalation_policy': '247b97499078a015cc6c586bc0a92de6',
                         'escalation_policy_id': 'POLICYID123',
                         'email_from': 'blah@foo.bar',
                         'integration_key': '247b97499078a015cc6c586bc0a92de6'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       'us-east-1', self.kms_alias)

            elif service == 'phantom':
                output_name = '{}/{}'.format(service, descriptor)
                creds = {'ph_auth_token': '6c586bc047b9749a92de29078a015cc6',
                         'url': 'phantom.foo.bar'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       self.region, self.kms_alias)

            elif service == 'slack':
                output_name = '{}/{}'.format(service, descriptor)
                creds = {'url': 'https://api.slack.com/web-hook-key'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       self.region, self.kms_alias)

            elif service == 'jira':
                output_name = '{}/{}'.format(service, descriptor)
                creds = {'username': 'jira@foo.bar',
                         'password': 'jirafoobar',
                         'url': 'jira.foo.bar',
                         'project_key': 'foobar',
                         'issue_type': 'Task',
                         'aggregate': 'no'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       'us-east-1', self.kms_alias)

            elif service == 'github':
                output_name = '{}/{}'.format(service, descriptor)
                creds = {'username': 'github-user',
                         'repository': 'github-user/github-repository',
                         'access_token': 'foobar',
                         'labels': 'test-label'}
                helpers.put_mock_creds(output_name, creds, self.secrets_bucket,
                                       'us-east-1', self.kms_alias)

    @staticmethod
    def _cleanup_old_secrets():
        """Remove the local secrets directory that may be left from previous runs"""
        temp_dir = os.path.join(tempfile.gettempdir(), 'stream_alert_secrets')

        # Check if the folder exists, and remove it if it does
        if os.path.isdir(temp_dir):
            shutil.rmtree(temp_dir)


def report_output(passed, cols):
    """Helper function to pretty print columns for reporting results

    Args:
        passed (bool): The pass status of the current test case
        cols (list): A list of columns to print as output
    """

    status = ('{}[Pass]{}'.format(COLOR_GREEN, COLOR_RESET) if passed else
              '{}[Fail]{}'.format(COLOR_RED, COLOR_RESET))

    print '{:>26}  {:<28}  {:<8}  ({}): {}'.format(status, *cols)


def check_untested_rules(all_test_rules):
    """Log warning message for rules that exist but do not have proper test events.

    Args:
        all_test_rules (set): A collection of all of the rules being tested
    """
    untested_rules = set(rule.Rule.rule_names()).difference(all_test_rules)
    if untested_rules:
        LOGGER_CLI.warn('%sNo test events configured for the following rules. Please add '
                        'corresponding tests for these rules in \'%s\' to avoid seeing '
                        'this warning\n\t%s%s', COLOR_YELLOW, TEST_EVENTS_DIR,
                        '\n\t'.join(untested_rules), COLOR_RESET)


def check_untested_files(all_test_rules):
    """Log warning message for test events that exist with invalid rule names.

    Args:
        all_test_rules (set): A collection of all of the rules being tested
    """
    invalid_rules = all_test_rules.difference(set(rule.Rule.rule_names()))
    if invalid_rules:
        LOGGER_CLI.warn('%sNo rules found in \'rules/\' that match the rules declared within '
                        '\'trigger_rules\' in a test event.  Please update the list of '
                        '\'trigger_rules\' with valid rule names to avoid seeing this '
                        'warning and any associated errors '
                        'above\n\t%s%s', COLOR_YELLOW, '\n\t'.join(invalid_rules), COLOR_RESET)


def check_invalid_rules_filters(rules_filter, all_test_rules):
    """Log warning message for filtered rules that do not exist.

    Args:
        rules_filter (set): A collection of rules to filter on, passed in by the user
        all_test_rules (set): A collection of all of the rules being tested
    """
    invalid_rules = rules_filter.difference(all_test_rules)
    if invalid_rules:
        LOGGER_CLI.warn('%sNo test events configured for the following rules being filtered. '
                        'This error could also be caused by a typo in the list of filtered '
                        'rules\n\t%s%s', COLOR_YELLOW, '\n\t'.join(invalid_rules), COLOR_RESET)


def stream_alert_test(options, config):
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
        # The Rule Processor and Alert Processor need environment variables for many things
        prefix = config['global']['account']['prefix']
        alerts_table = '{}_streamalert_alerts'.format(prefix)
        os.environ['ALERT_PROCESSOR'] = '{}_streamalert_alert_processor'.format(prefix)
        os.environ['ALERTS_TABLE'] = alerts_table
        os.environ['AWS_DEFAULT_REGION'] = config['global']['account']['region']
        os.environ['CLUSTER'] = run_options.get('cluster') or ''

        if not options.debug:
            # Add a filter to suppress a few noisy log messages
            LOGGER_SA.addFilter(SuppressNoise())

        # Create an in memory logging buffer to be used to caching all error messages
        log_mem_handler = get_log_memory_handler()

        # Check if the rule processor should be run for these tests
        # Using NOT set.isdisjoint will check to see if there are commonalities between
        # the options in 'processor' and {'rule', 'all'}
        test_rules = (not run_options.get('processor').isdisjoint({'rule', 'all'})
                      if run_options.get('processor') else
                      run_options.get('command') == 'live-test' or
                      run_options.get('command') == 'validate-schemas')

        # Check if the alert processor should be run for these tests
        # Using NOT set.isdisjoint will check to see if there are commonalities between
        # the options in 'processor' and {'alert', 'all'}
        test_alerts = (not run_options.get('processor').isdisjoint({'alert', 'all'})
                       if run_options.get('processor') else
                       run_options.get('command') == 'live-test')

        validate_schemas = options.command == 'validate-schemas'

        rules_filter = run_options.get('rules', {})
        files_filter = run_options.get('files', {})

        # Run the rule processor for all rules or designated rule set
        if context.mocked:
            helpers.setup_mock_dynamodb_rules_table(config)
            helpers.setup_mock_alerts_table(alerts_table)
            # Mock S3 bucket for lookup tables testing
            helpers.mock_s3_bucket(config)

        rule_proc_tester = RuleProcessorTester(context, config, test_rules)
        alert_proc_tester = AlertProcessorTester(config, context)

        for _ in range(run_options.get('repeat', 1)):
            for alerts in rule_proc_tester.test_processor(rules_filter,
                                                          files_filter,
                                                          validate_schemas):
                # If the alert processor should be tested, process any alerts
                if test_alerts:
                    alert_proc_tester.test_processor(alerts)

            # Report summary information for the alert processor if it was ran
            if test_alerts:
                AlertProcessorTester.report_output_summary()

        all_test_rules = None
        if rules_filter:
            all_test_rules = helpers.get_rules_from_test_events(TEST_EVENTS_DIR)
            check_invalid_rules_filters(rules_filter, all_test_rules)

        # If this is not just a validation run, and rule/file filters are not in place
        # then warn the user if there are test files without corresponding rules
        # Also check all of the rule files to make sure they have tests configured
        if not (validate_schemas or rules_filter or files_filter):
            all_test_rules = all_test_rules or helpers.get_rules_from_test_events(TEST_EVENTS_DIR)
            check_untested_files(all_test_rules)
            check_untested_rules(all_test_rules)

        if not (rule_proc_tester.all_tests_passed and
                alert_proc_tester.all_tests_passed):
            return 1 # will exit with error

        # If there are any log records in the memory buffer, then errors occurred somewhere
        if log_mem_handler.buffer:
            # Release the MemoryHandler so we can do some other logging now
            logging.getLogger().removeHandler(log_mem_handler)
            LOGGER_CLI.error('%sSee %d miscellaneous error(s) below '
                             'that were encountered and may need to be addressed%s',
                             COLOR_RED, len(log_mem_handler.buffer), COLOR_RESET)

            log_mem_handler.setTarget(LOGGER_CLI)
            log_mem_handler.flush()

            return 1 # will exit with error

        return 0 # will exit without error

    result = run_tests(options, context)

    if run_options.get('stats'):
        stats.print_rule_stats()

    sys.exit(result)

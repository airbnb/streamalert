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

import base64
import json
import logging
import os
import random
import re
import time
import zlib

from mock import Mock, patch

import boto3
from moto import mock_lambda, mock_kms, mock_s3, mock_sns

from stream_alert.alert_processor import main as StreamOutput
from stream_alert.rule_processor.handler import StreamAlert
from stream_alert_cli.helpers import (
    _create_lambda_function,
    _put_mock_creds,
    _put_mock_s3_object
)

from stream_alert_cli.outputs import load_outputs_config
from stream_alert_cli.logger import LOGGER_CLI, LOGGER_SA

# import all rules loaded from the main handler
# pylint: disable=unused-import
import stream_alert.rule_processor.main
# pylint: enable=unused-import

DIR_RULES = 'test/integration/rules'
DIR_TEMPLATES = 'test/integration/templates'
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
        super(self.__class__, self).__init__()
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

        Returns:
            [generator] yields a tuple containig a boolean of test status and
                a list of alerts to run through the alert processor
        """
        all_tests_passed = True

        for rule_file, rule_name in get_rule_test_files(rules):
            with open(os.path.join(DIR_RULES, rule_file), 'r') as rule_file_handle:
                try:
                    contents = json.load(rule_file_handle)
                except Exception as err:
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
                    self.format_record(test_record))

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
                        'rule',
                        test_record['service'],
                        '{} [trigger={}]'.format(test_record['description'],
                                                 expected_alerts)])

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

    def test_rule(self, rule_name, test_record, formatted_record):
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

    def format_record(self, test_record):
        """Create a properly formatted Kinesis, S3, or SNS record.

        Supports a dictionary or string based data record.  Reads in
        event templates from the test/integration/templates folder.

        Args:
            test_record: Test record metadata dict with the following structure:
                data - string or dict of the raw data
                description - a string describing the test that is being performed
                trigger - bool of if the record should produce an alert
                source - which stream/s3 bucket originated the data
                service - which aws service originated the data
                compress (optional) - if the payload needs to be gzip compressed or not

        Returns:
            dict in the format of the specific service
        """
        service = test_record['service']
        source = test_record['source']
        compress = test_record.get('compress')

        data_type = type(test_record['data'])
        if data_type == dict:
            data = json.dumps(test_record['data'])
        elif data_type in (unicode, str):
            data = test_record['data']
        else:
            LOGGER_CLI.info('Invalid data type: %s', type(test_record['data']))
            return

        # Get the template file for this particular service
        template_path = os.path.join(DIR_TEMPLATES, '{}.json'.format(service))
        with open(template_path, 'r') as service_template:
            try:
                template = json.load(service_template)
            except ValueError as err:
                LOGGER_CLI.error('Error loading %s.json: %s', service, err)
                return

        if service == 's3':
            # Set the S3 object key to a random value for testing
            test_record['key'] = ('{:032X}'.format(random.randrange(16**32)))
            template['s3']['object']['key'] = test_record['key']
            template['s3']['object']['size'] = len(data)
            template['s3']['bucket']['arn'] = 'arn:aws:s3:::{}'.format(source)
            template['s3']['bucket']['name'] = source

            # Create the mocked s3 object in the designated bucket with the random key
            _put_mock_s3_object(source, test_record['key'], data, 'us-east-1')

        elif service == 'kinesis':
            if compress:
                kinesis_data = base64.b64encode(zlib.compress(data))
            else:
                kinesis_data = base64.b64encode(data)

            template['kinesis']['data'] = kinesis_data
            template['eventSourceARN'] = 'arn:aws:kinesis:us-east-1:111222333:stream/{}'.format(
                source)

        elif service == 'sns':
            template['Sns']['Message'] = data
            template['EventSubscriptionArn'] = 'arn:aws:sns:us-east-1:111222333:{}'.format(
                source)
        else:
            LOGGER_CLI.info('Invalid service %s', service)

        return template


class AlertProcessorTester(object):
    """Class to encapsulate testing the alert processor"""
    _alert_fail_pass = [0, 0]

    def __init__(self):
        super(self.__class__, self).__init__()
        self.kms_alias = 'alias/stream_alert_secrets_test'
        self.secrets_bucket = 'test.streamalert.secrets'
        self.outputs_config = load_outputs_config()

    @patch('urllib2.urlopen')
    def test_processor(self, alerts, url_mock):
        """Perform integration tests for the 'alert' Lambda function

        Args:
            alerts [list]: list of alerts to be processed
            url_mock [mock.patch]: patch to mock out urlopen calls

        Return:
            [bool] boolean indicating the status of the alert processor dispatching
        """
        status = True
        # Set the logger level to info so its not too noisy
        StreamOutput.LOGGER.setLevel(logging.ERROR)
        for alert in alerts:
            outputs = alert['metadata'].get('outputs', [])
            self.setup_outputs(outputs, url_mock)
            event = {'Records': [{'Sns': {'Message': json.dumps({'default': alert})}}]}
            context = Mock()
            context.invoked_function_arn = (
                'arn:aws:lambda:us-east-1:0123456789012:'
                'function:streamalert_alert_processor:production')
            context.function_name = 'test_streamalert_alert_processor'
            for passed, output in StreamOutput.handler(event, context):
                status = status and passed
                service, descriptor = output.split(':')
                message = 'sending alert to \'{}\''.format(descriptor)
                report_output([
                    passed,
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

    def setup_outputs(self, outputs, url_mock):
        """Helper function to handler any output setup"""
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
                _create_lambda_function(function, 'us-east-1')
            elif service == 'pagerduty':
                output_name = ('/').join([service, descriptor])
                creds = {'service_key': '247b97499078a015cc6c586bc0a92de6'}
                _put_mock_creds(output_name, creds, self.secrets_bucket,
                                'us-east-1', self.kms_alias)

                # Set the patched urlopen.getcode return value to 200
                url_mock.return_value.getcode.return_value = 200
            elif service == 'phantom':
                output_name = ('/').join([service, descriptor])
                creds = {'ph_auth_token': '6c586bc047b9749a92de29078a015cc6',
                         'url': 'phantom.foo.bar'}
                _put_mock_creds(output_name, creds, self.secrets_bucket,
                                'us-east-1', self.kms_alias)

                # Set the patched urlopen.getcode return value to 200
                url_mock.return_value.getcode.return_value = 200
                # Phantom needs a container 'id' value in the http response
                url_mock.return_value.read.return_value = '{"id": 1948}'
            elif service == 'slack':
                output_name = ('/').join([service, descriptor])
                creds = {'url': 'https://api.slack.com/web-hook-key'}
                _put_mock_creds(output_name, creds, self.secrets_bucket,
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

    print '\t{}\t{}\t({}): {}'.format(status, *cols[1:])


def get_rule_test_files(filter_rules):
    """Helper to get rule files to be tested

    Args:
        filter_rules [str]: Comma separated list of rules to run tests against

    Returns:
        [generator] Yields back the rule file path and rule name
    """
    rules_to_test = ([], filter_rules.split(','))[bool(filter_rules)]

    for _, _, test_rule_files in os.walk(DIR_RULES):
        for rule_file in test_rule_files:
            rule_name = rule_file.split('.')[0]

            # If specific rules are being tested, skip files
            # that do not match those rules
            if rules_to_test and rule_name not in rules_to_test:
                continue

            yield rule_file, rule_name


@mock_lambda
@mock_sns
@mock_s3
@mock_kms
def stream_alert_test(options):
    """Integration testing handler

    Args:
        options: dict of CLI options: (func, env, source)
    """
    # Instantiate two status items - one for the rule processor
    # and one for the alert processor
    rp_status, ap_status = True, True

    if options.debug:
        LOGGER_SA.setLevel(logging.DEBUG)
        LOGGER_CLI.setLevel(logging.DEBUG)
    else:
        # Add a filter to suppress a few noisy log messages
        LOGGER_SA.addFilter(TestingSuppressFilter())

    test_alerts = options.processor == 'alert'
    # See if the alert processor should be run for these tests
    run_ap = test_alerts or options.processor == 'all'
    rule_proc_tester = RuleProcessorTester(not test_alerts)
    # Run the rule processor for all rules or designated rule set
    for status, alerts in rule_proc_tester.test_processor(options.rules):
        # If the alert processor should be tested, pass any alerts to it
        # and store the status over time
        if run_ap:
            # Update the overall alert processor status with the ongoing status
            ap_status = AlertProcessorTester().test_processor(alerts) and ap_status

        # Update the overall rule processor status with the ongoing status
        rp_status = status and rp_status

    # Report summary information for the alert processor if it was ran
    if run_ap:
        AlertProcessorTester.report_output_summary()

    if not (rp_status and ap_status):
        os._exit(1)

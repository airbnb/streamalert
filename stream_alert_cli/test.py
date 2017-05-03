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

import boto3
from moto import mock_s3

from stream_alert.rule_processor.handler import StreamAlert
from stream_alert_cli.logger import LOGGER_CLI, LOGGER_SA
# import all rules loaded from the main handler
# pylint: disable=unused-import
import stream_alert.rule_processor.main
# pylint: enable=unused-import

BOTO_MOCKER = mock_s3()

DIR_RULES = 'test/integration/rules'
DIR_TEMPLATES = 'test/integration/templates'
COLOR_RED = '\033[0;31;1m'
COLOR_GREEN = '\033[0;32;1m'
COLOR_RESET = '\033[0m'

def report_output(cols, failed):
    """Helper function to pretty print columns
    Args:
        cols: A list of columns to print (service, test description)
        failed: Boolean indicating if this rule failed
    """

    status = ('{}[Pass]{}'.format(COLOR_GREEN, COLOR_RESET),
              '{}[Fail]{}'.format(COLOR_RED, COLOR_RESET))[failed]

    print '\t{}\ttest ({}): {}'.format(status, *cols)

def test_rule(rule_name, test_record, formatted_record):
    """Feed formatted records into StreamAlert and check for alerts
    Args:
        rule_name: The rule name being tested
        test_record: A single record to test
        formatted_record: A properly formatted version of record for the service to be tested

    Returns:
        boolean indicating if this rule passed
    """
    event = {'Records': [formatted_record]}

    trigger_count = test_record.get('trigger_count')
    if trigger_count:
        expected_alert_count = trigger_count
    else:
        expected_alert_count = (0, 1)[test_record['trigger']]

    alerts = StreamAlert(return_alerts=True).run(event, None)
    # we only want alerts for the specific rule passed in
    matched_alert_count = len([x for x in alerts if x['metadata']['rule_name'] == rule_name])

    report_output([test_record['service'], test_record['description']],
                  matched_alert_count != expected_alert_count)

    return matched_alert_count == expected_alert_count

def format_record(test_record):
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
        template['s3']['bucket']['arn'] = 'arn:aws:s3:::{}'.format(source)
        template['s3']['bucket']['name'] = source

        # Create the mocked s3 object in the designated bucket with the random key
        put_mocked_s3_object(source, test_record['key'], data)

    elif service == 'kinesis':
        if compress:
            kinesis_data = base64.b64encode(zlib.compress(data))
        else:
            kinesis_data = base64.b64encode(data)

        template['kinesis']['data'] = kinesis_data
        template['eventSourceARN'] = 'arn:aws:kinesis:us-east-1:111222333:stream/{}'.format(source)

    elif service == 'sns':
        template['Sns']['Message'] = data
        template['EventSubscriptionArn'] = 'arn:aws:sns:us-east-1:111222333:{}'.format(source)
    else:
        LOGGER_CLI.info('Invalid service %s', service)

    return template

def check_keys(test_record):
    """Check the test_record contains the required keys

    Args:
        test_record: Test record metadata dict

    Returns:
        boolean result of key set comparison
    """
    req_keys = {
        'data',
        'description',
        'service',
        'source',
        'trigger'
    }

    optional_keys = {
        'trigger_count',
        'compress'
    }

    record_keys = set(test_record.keys())
    return (
        req_keys == record_keys or
        any(x in test_record for x in optional_keys)
    )

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

def test_alert_rules():
    """Integration test the 'Alert' Lambda function with various record types

    Returns:
        boolean indicating if all tests passed
    """
    # Start the mock_s3 instance here so we can test with mocked objects project-wide
    BOTO_MOCKER.start()
    tests_passed = True

    for root, _, rule_files in os.walk(DIR_RULES):
        for rule_file in rule_files:
            rule_name = rule_file.split('.')[0]
            rule_file_path = os.path.join(root, rule_file)

            # Print rule name for section header
            print '\n{}'.format(rule_name)

            with open(rule_file_path, 'r') as rule_file_handle:
                try:
                    contents = json.load(rule_file_handle)
                    test_records = contents['records']
                except (ValueError, KeyError) as err:
                    tests_passed = False
                    LOGGER_CLI.error('Improperly formatted file (%s) %s: %s',
                                     rule_file_path, type(err).__name__, err)
                    continue

            if len(test_records) == 0:
                tests_passed = False
                LOGGER_CLI.error('No records to test for %s', rule_name)
                continue

            # Go over the records and test the applicable rule
            for test_record in test_records:
                if not check_keys(test_record):
                    report_output([test_record['service'],
                                   'Improperly formatted record: {}'.format(test_record)],
                                  True)
                    tests_passed = False
                    continue

                apply_helpers(test_record)
                formatted_record = format_record(test_record)
                tests_passed = test_rule(rule_name, test_record, formatted_record) and tests_passed

    BOTO_MOCKER.stop()

    return tests_passed

def put_mocked_s3_object(bucket_name, key_name, body_value):
    """Create a mock AWS S3 object for testing

    Args:
        bucket_name: the bucket in which to place the object (string)
        key_name: the key to use for the S3 object (string)
        body_value: the actual value to use for the object (string)
    """
    s3_resource = boto3.resource('s3', region_name='us-east-1')
    s3_resource.create_bucket(Bucket=bucket_name)
    obj = s3_resource.Object(bucket_name, key_name)
    response = obj.put(Body=body_value)

    # Log if this was not a success (this should not fail for mocked objects)
    if response['ResponseMetadata']['HTTPStatusCode'] != 200:
        LOGGER_CLI.error('Could not put mock object with key %s in s3 bucket with name %s',
                         key_name,
                         bucket_name)

def stream_alert_test(options):
    """Integration testing handler

    Args:
        options: dict of CLI options: (func, env, source)
    """
    if options.debug:
        LOGGER_SA.setLevel(logging.DEBUG)
    else:
        LOGGER_SA.setLevel(logging.INFO)

    if options.processor == 'rule':
        passed = test_alert_rules()

    elif options.processor == 'alert':
        # TODO(jack) test output
        raise NotImplementedError

    if not passed:
        os._exit(1)
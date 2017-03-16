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

import boto3
from moto import mock_s3
from stream_alert.handler import StreamAlert
# import all rules loaded from the main handler
import main

LOGGER_SA = logging.getLogger('StreamAlert')
LOGGER_CLI = logging.getLogger('StreamAlertCLI')
LOGGER_CLI.setLevel(logging.INFO)

BOTO_MOCKER = mock_s3()

DIR_RULES = 'test/integration/rules'
DIR_TEMPLATES = 'test/integration/templates'
COLOR_RED = '\033[0;31;1m'
COLOR_GREEN = '\033[0;32;1m'
COLOR_RESET = '\033[0m'

def report_output(cols, force_exit):
    """Helper function to pretty print columns
    Args:
        cols: A list of columns to print (test description, pass|fail)
        force_exit: Boolean to break exectuion of integration testing
    """
    print '\t{}\ttest ({}): {}'.format(*cols)
    if force_exit:
        os._exit(1)

def test_rule(rule_name, test_file_contents):
    """Feed formatted records into StreamAlert and check for alerts
    Args:
        rule_name: The rule name being tested
        test_file_contents: The dictionary of the loaded test fixture file
    """
    # rule name header
    print '\n{}'.format(rule_name)

    for record in test_file_contents['records']:
        service = record['service']
        service_record_key = '{}_record'.format(service)
        event = {'Records': [record[service_record_key]]}

        expected_alert_count = (0, 1)[record['trigger']]

        alerts = StreamAlert(return_alerts=True).run(event, None)
        # we only want alerts for the specific rule passed in
        matched_alert_count = len([x for x in alerts if x['rule_name'] == rule_name])

        if matched_alert_count == expected_alert_count:
            result = '{}[Pass]{}'.format(COLOR_GREEN, COLOR_RESET)
            force_exit = False
        else:
            result = '{}[Fail]{}'.format(COLOR_RED, COLOR_RESET)
            force_exit = True

        report_output([result, service, record['description']], force_exit)

def format_record(test_record):
    """Create a properly formatted Kinesis, S3, or SNS record.

    Supports a dictionary or string based data record.  Reads in
    event templates from the test/integration/templates folder.

    Args:
        test_record: Test record metadata dict with the following structure:
            data - string or dict of the raw data
            trigger - bool of if the record should produce an alert
            source - which stream/s3 bucket originated the data
            service - which aws service originated the data

    Returns:
        dict in the format of the specific service
    """
    service = test_record['service']
    source = test_record['source']

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
        template['kinesis']['data'] = base64.b64encode(data)
        template['eventSourceARN'] = 'arn:aws:kinesis:us-east-1:111222333:stream/{}'.format(source)
    elif service == 'sns':
        # TODO implement sns testing
        pass
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
    record_keys = set(test_record.keys())
    return req_keys == record_keys

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
    """Integration test the 'Alert' Lambda function with various record types"""
    # Start the mock_s3 instance here so we can test with mocked objects project-wide
    BOTO_MOCKER.start()

    for root, _, rule_files in os.walk(DIR_RULES):
        for rule_file in rule_files:
            rule_name = rule_file.split('.')[0]
            rule_file_path = os.path.join(root, rule_file)

            with open(rule_file_path, 'r') as rule_file_handle:
                try:
                    contents = json.load(rule_file_handle)
                except ValueError as err:
                    LOGGER_CLI.error('Error loading %s: %s', rule_file, err)
                    continue

            test_records = contents.get('records')
            if not test_records:
                LOGGER_CLI.error('Improperly formatted test file: %s', rule_file_path)
                continue
            elif len(test_records) == 0:
                LOGGER_CLI.error('No records to test for %s', rule_name)
                continue

            # Go backwards over the records so we can remove improper ones
            # safely without unnecessary copying/modifying of the list
            for test_record in reversed(test_records):
                if not check_keys(test_record):
                    LOGGER_CLI.error('Discarding improperly formatted record for service %s: %s',
                                     test_record['service'],
                                     test_record)
                    # Removing an improperly formatted record here allows us to
                    # continue with current tests, while still logging it above
                    test_records.pop(test_records.index(test_record))
                    continue

                apply_helpers(test_record)
                service_record_key = '{}_record'.format(test_record['service'])
                test_record[service_record_key] = format_record(test_record)

            test_rule(rule_name, contents)

    BOTO_MOCKER.stop()

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

    if options.func == 'alert':
        test_alert_rules()

    elif options.func == 'output':
        # TODO(jack) test output
        raise NotImplementedError

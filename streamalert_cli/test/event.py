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
import base64
import json
import re
import time
import zlib
from unittest.mock import patch

from streamalert.classifier.parsers import ParserBase
from streamalert.shared import rule
from streamalert.shared.logger import get_logger
from streamalert_cli.test.mocks import LookupTableMocks, ThreatIntelMocks

LOGGER = get_logger(__name__)


class TestEvent:

    ACCEPTABLE_DATA_KEYS = {'data', 'override_record'}
    REQUIRED_KEYS = {'description', 'log', 'service', 'source'}
    OPTIONAL_KEYS = {
        'compress',
        'trigger_rules',
        'classify_only',
        'skip_publishers',
        'publisher_tests',
        'test_fixtures',
    }

    def __init__(self, test_data):
        self._event = test_data
        self.error = None
        self.record = None
        self._suppressed = False

    # One of either 'data' or 'override_record' is required
    @property
    def data(self):
        return self._event.get('data')

    @property
    def override_record(self):
        return self._event.get('override_record')

    # The 'description', 'log', 'service', and 'source' keys are not optional
    @property
    def description(self):
        return self._event['description']

    @property
    def log(self):
        return self._event['log']

    @property
    def service(self):
        return self._event['service']

    @property
    def source(self):
        return self._event['source']

    # The 'compress', 'trigger_rules', 'classify_only', 'skip_publishers',
    # and 'test_fixtures' keys are optional
    @property
    def compress(self):
        return self._event.get('compress', False)

    @property
    def trigger_rules(self):
        return self._event.get('trigger_rules', [])

    @property
    def classify_only(self):
        return self._event.get('classify_only', False)

    @property
    def skip_publishers(self):
        return self._event.get('skip_publishers', False)

    @property
    def publisher_tests(self):
        return [] if self.skip_publishers else self._event.get('publisher_tests', [])

    @property
    def test_fixtures(self):
        return self._event.get('test_fixtures', {})

    @property
    def lookup_table_fixtures(self):
        return self.test_fixtures.get('lookup_tables', {})

    @property
    def threat_intel_fixtures(self):
        return self.test_fixtures.get('threat_intel', {})

    @property
    def suppressed(self):
        return self._suppressed

    @suppressed.setter
    def suppressed(self, value):
        # If something else is suppressing this already, keep the suppression
        self._suppressed = self._suppressed or value
        return self._suppressed

    def is_valid(self, config):
        """Check if the test event contains the required keys

        Returns:
            bool: True if the proper keys are present
        """
        if not isinstance(self._event, dict):
            self.error = f'Invalid type for event: {type(self._event)}; should be dict'
            return False

        test_event_keys = set(self._event)
        if not self.REQUIRED_KEYS.issubset(test_event_keys):
            req_key_diff = self.REQUIRED_KEYS.difference(test_event_keys)
            missing_keys = ', '.join(f"\'{key}\'" for key in req_key_diff)
            self.error = f'Missing required key(s) in test event: {missing_keys}'
            return False

        if not (self.data or self.override_record):
            self.error = 'Test event must contain either \'data\' or \'override_record\''
            return False

        if not self._event.get('classify_only') and 'trigger_rules' not in test_event_keys:
            self.error = (
                'Test events that are not \'classify_only\' should have \'trigger_rules\' '
                'defined')
            return False

        if self.log not in config['logs']:
            self.error = f'No defined schema in config for log type: {self.log}'
            return False

        if key_diff := test_event_keys.difference(self.REQUIRED_KEYS | self.OPTIONAL_KEYS
                                                  | self.ACCEPTABLE_DATA_KEYS):
            extra_keys = ', '.join(f"\'{key}\'" for key in key_diff)
            LOGGER.warning('Additional unnecessary keys in test event: %s', extra_keys)

        return True

    def check_for_rules(self, rules):
        if not rules:  # no filtering on rules is being performed
            return True

        expected_rules = set(self.trigger_rules) - rule.Rule.disabled_rules()
        self.suppressed = not bool(expected_rules.intersection(rules))
        return not self.suppressed

    def setup_fixtures(self):
        LOGGER.debug('Setting up fixtures')
        LookupTableMocks.add_fixtures(self.lookup_table_fixtures)
        ThreatIntelMocks.add_fixtures(self.threat_intel_fixtures)

    def prepare(self, config):
        if not self.is_valid(config):
            return False

        if not self.format_test_record(config):
            return False

        # Apply any fixtures needed for this test event
        self.setup_fixtures()

        return True

    def format_test_record(self, config):
        """Create a properly formatted Kinesis, S3, or SNS record.

        Supports a dictionary or string based data record.  Reads in
        event templates from the tests/integration/templates folder.

        Args:
            config (dict): The loaded configuration

        Returns:
            dict: in the format of the specific service
        """
        self._apply_helpers()
        self._apply_defaults(config)

        rec_data = self.data
        if isinstance(rec_data, dict):
            rec_data = json.dumps(rec_data)
        elif not isinstance(self.data, str):
            self.error = f'Invalid data type: {type(rec_data)}'
            return False

        if self._event['service'] not in {'s3', 'kinesis', 'sns', 'streamalert_app'}:
            self.error = f'Unsupported service: {self.service}'
            return False

        # Set a formatted record for this particular service
        self.record = self._apply_service_template(rec_data)

        return True

    def _apply_service_template(self, data):
        """Provides a pre-configured template that reflects incoming payload from a service

        Args:
            service (str): The service for the payload template

        Returns:
            dict: Template of the payload for the given service
        """
        if self.service == 's3':
            # Assign the s3 mock for this data
            self._setup_s3_mock(data)
            return {
                'eventVersion': '2.0',
                'eventTime': '1970-01-01T00:00:00.000Z',
                'requestParameters': {
                    'sourceIPAddress': '127.0.0.1'
                },
                's3': {
                    'configurationId': ',,,',
                    'object': {
                        'eTag': '...',
                        'sequencer': '...',
                        'key': 'test_object_key',
                        'size': len(data)
                    },
                    'bucket': {
                        'arn': f'arn:aws:s3:::{self.source}',
                        'name': self.source,
                        'ownerIdentity': {
                            'principalId': 'EXAMPLE'
                        }
                    },
                    's3SchemaVersion': '1.0'
                },
                'responseElements': {
                    'x-amz-id-2': ('EXAMPLE123/foo/bar'),
                    'x-amz-request-id': '...'
                },
                'awsRegion': 'us-east-1',
                'eventName': 'ObjectCreated:Put',
                'userIdentity': {
                    'principalId': 'EXAMPLE'
                },
                'eventSource': 'aws:s3'
            }

        if self.service == 'kinesis':
            if self.compress:
                data = zlib.compress(data)

            kinesis_data = base64.b64encode(data.encode() if isinstance(data, str) else data)

            return {
                'eventID': '...',
                'eventVersion': '1.0',
                'kinesis': {
                    'approximateArrivalTimestamp': 1428537600,
                    'partitionKey': 'partitionKey-3',
                    'data': kinesis_data,
                    'kinesisSchemaVersion': '1.0',
                    'sequenceNumber': ',,,'
                },
                'invokeIdentityArn': 'arn:aws:iam::EXAMPLE',
                'eventName': 'aws:kinesis:record',
                'eventSourceARN': f'arn:aws:kinesis:us-east-1:123456789012:stream/{self.source}',
                'eventSource': 'aws:kinesis',
                'awsRegion': 'us-east-1'
            }

        if self.service == 'sns':
            return {
                'EventVersion': '1.0',
                'EventSubscriptionArn': f'arn:aws:sns:us-east-1:123456789012:{self.source}',
                'EventSource': 'aws:sns',
                'Sns': {
                    'SignatureVersion': '1',
                    'Timestamp': '1970-01-01T00:00:00.000Z',
                    'Signature': 'EXAMPLE',
                    'SigningCertUrl': 'EXAMPLE',
                    'MessageId': '95df01b4-ee98-5cb9-9903-4c221d41eb5e',
                    'Message': data,
                    'MessageAttributes': {
                        'Test': {
                            'Type': 'String',
                            'Value': 'TestString'
                        }
                    },
                    'Type': 'Notification',
                    'UnsubscribeUrl': '...',
                    'TopicArn': f'arn:aws:sns:us-east-1:123456789012:{self.source}',
                    'Subject': '...'
                }
            }

        if self.service == 'streamalert_app':
            return {'streamalert_app': self.source, 'logs': [data]}

    def _apply_helpers(self):
        """Detect and apply helper functions to test event data

        Helpers are declared in test fixtures via the following keyword:
        "<helpers:helper_name>"

        Supported helper functions:
            last_hour: return the current epoch time minus 60 seconds to pass the
                       last_hour rule helper.
        """
        # declare all helper functions here, they should always return a string
        record_helpers = {'last_hour': lambda: str(int(time.time()) - 60)}
        helper_regex = re.compile(r'<helper:(?P<helper>\w+)>')

        def _find_and_apply_helpers(test_record):
            """Apply any helpers to the passed in test_record"""
            for key, value in test_record.items():
                if isinstance(value, str):
                    test_record[key] = re.sub(helper_regex,
                                              lambda match: record_helpers[match.group('helper')](),
                                              value)
                elif isinstance(value, dict):
                    _find_and_apply_helpers(test_record[key])

        _find_and_apply_helpers(self._event)

    @staticmethod
    def _setup_s3_mock(data):
        s3_mocker = patch('streamalert.classifier.payload.s3.boto3.resource').start()
        s3_mocker.return_value.Bucket.return_value.download_fileobj = (
            lambda k, d: d.write(json.dumps(data).encode()))

    def _apply_defaults(self, config):
        """Apply default values to the given test event"""
        if not self.override_record:
            return

        # The existence of this is checked in the is_valid function
        event_log = config['logs'].get(self.log)

        configuration = event_log.get('configuration', {})
        schema = configuration.get('envelope_keys', event_log['schema'])

        # Add apply default values based on the declared schema
        default_test_event = {
            key: ParserBase.default_optional_values(value)
            for key, value in schema.items()
        }

        # Overwrite the fields included in the 'override_record' field,
        # and update the test event with a full 'data' key
        default_test_event |= self.override_record
        self._event['data'] = default_test_event

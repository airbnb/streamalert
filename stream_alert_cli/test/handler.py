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
from __future__ import print_function

import base64
from collections import defaultdict
import json
import os
import re
import time
import zlib

from mock import patch, MagicMock

from stream_alert.alert_processor import main as alert_processor
from stream_alert.alert_processor.helpers import compose_alert
from stream_alert.alert_processor.outputs.output_base import OutputDispatcher
from stream_alert.classifier import classifier
from stream_alert.classifier.parsers import ParserBase
from stream_alert.rules_engine import rules_engine
from stream_alert.shared import rule
from stream_alert.shared.logger import get_logger
from stream_alert.shared.stats import get_rule_stats
from stream_alert_cli.helpers import check_credentials
from stream_alert_cli.test.format import format_green, format_red, format_underline, format_yellow
from stream_alert_cli.test.mocks import mock_lookup_table_results, mock_threat_intel_query_results
from stream_alert_cli.test.results import TestEventFile, TestResult

LOGGER = get_logger(__name__)


def test_handler(options, config):
    """Handler for starting the test framework

    Args:
        options (argparse.Namespace): Parsed arguments
        config (CLIConfig): Loaded StreamAlert config

    Returns:
        bool: False if errors occurred, True otherwise
    """
    result = True
    opts = vars(options)
    repeat = opts.get('repeat', 1)
    for i in range(repeat):
        if repeat != 1:
            print('\nRepetition #', i+1)
        result = result and TestRunner(options, config).run()

    if opts.get('stats'):
        print(get_rule_stats())
    return result


class TestRunner(object):
    """TestRunner to handle running various tests"""

    class Types(object):
        """Simple types enum for test types"""
        CLASSIFY = 'classifier'
        RULES = 'rules'
        LIVE = 'live'

    def __init__(self, options, config):
        self._config = config
        self._options = options
        self._type = options.subcommand
        self._files = options.files
        self._rules = options.rules
        self._files_dir = os.path.join(options.files_dir, '')  # ensure theres a trailing slash
        self._verbose = options.verbose
        self._quiet = options.quiet
        self._s3_mocker = patch('stream_alert.classifier.payload.s3.boto3.resource').start()
        self._errors = defaultdict(list)  # cache errors to be logged at the endpoint
        self._tested_rules = set()
        self._threat_intel_mock = mock_threat_intel_query_results()
        self._lookup_tables_mock = mock_lookup_table_results()
        self._passed = 0
        self._failed = 0
        prefix = self._config['global']['account']['prefix']
        patch.dict(
            os.environ,
            {
                'CLUSTER': 'local-test',
                'STREAMALERT_PREFIX': prefix,
                'AWS_ACCOUNT_ID': self._config['global']['account']['aws_account_id'],
                'ALERTS_TABLE': '{}_streamalert_alerts'.format(prefix),
            }
        ).start()

    @staticmethod
    def _run_classification(record):
        """Create a fresh classifier and classify the record, returning the result"""
        with patch.object(classifier, 'SQSClient'), patch.object(classifier, 'FirehoseClient'):
            _classifier = classifier.Classifier()
            return _classifier.run(records=[record])

    def _run_rules_engine(self, record):
        """Create a fresh rules engine and process the record, returning the result"""
        with patch.object(rules_engine.ThreatIntel, '_query') as ti_mock, \
             patch.object(rules_engine.LookupTables, 'load_lookup_tables') as lt_mock, \
             patch.object(rules_engine, 'AlertForwarder'), \
             patch.object(rules_engine, 'RuleTable') as rule_table, \
             patch('rules.helpers.base.random_bool', return_value=True):

            # Emptying out the rule table will force all rules to be unstaged, which causes
            # non-required outputs to get properly populated on the Alerts that are generated
            # when running the Rules Engine.
            rule_table.return_value = False

            ti_mock.side_effect = self._threat_intel_mock

            # pylint: disable=protected-access
            rules_engine.LookupTables._tables = self._lookup_tables_mock
            lt_mock.return_value = rules_engine.LookupTables
            _rules_engine = rules_engine.RulesEngine()

            return _rules_engine.run(records=record)

    @staticmethod
    def _run_alerting(record):
        """Create a fresh alerts processor and send the alert(s), returning the result"""
        with patch.object(alert_processor, 'AlertTable'):
            alert_proc = alert_processor.AlertProcessor()

            return alert_proc.run(event=record.dynamo_record())

    def _check_prereqs(self):
        if self._type == self.Types.LIVE:
            return check_credentials()

        return True

    def _finalize(self):
        summary = [
            format_underline('\nSummary:\n'),
            'Total Tests: {}'.format(self._passed + self._failed),
            format_green('Pass: {}'.format(self._passed)) if self._passed else 'Pass: 0',
            format_red('Fail: {}\n'.format(self._failed)) if self._failed else 'Fail: 0\n',
        ]

        print('\n'.join(summary))

        for path in sorted(self._errors):
            for error in self._errors[path]:
                message = '({}) {}'.format(path, error) if path != 'error' else error
                LOGGER.error(message)

        # If rule are being tested and no filtering is being performed, log any untested rules
        if self._testing_rules and not self._is_filtered:
            all_rules = set(rule.Rule.rule_names()) - rule.Rule.disabled_rules()
            untested_rules = sorted(all_rules.difference(self._tested_rules))
            if not untested_rules:
                return
            print(format_yellow('No test events configured for the following rules:'))
            for rule_name in untested_rules:
                print(format_yellow(rule_name))

    @property
    def _is_filtered(self):
        return bool(self._files or self._rules)

    @property
    def _testing_rules(self):
        return self._type in {self.Types.RULES, self.Types.LIVE}

    def _contains_filtered_rules(self, event):
        if not self._rules:
            return True

        expected_rules = set(event.get('trigger_rules', [])) - rule.Rule.disabled_rules()
        return bool(expected_rules.intersection(self._rules))

    def run(self):
        """Run the tests"""
        if not self._check_prereqs():
            return

        print('\nRunning tests for files found in: {}'.format(self._files_dir))

        for event_file in self._get_test_files():
            test_event = TestEventFile(event_file.replace(self._files_dir, ''))
            # Iterate over the individual test events in the file
            for idx, original_event, event in self._load_test_file(event_file):
                if not event:
                    continue

                if not self._contains_filtered_rules(original_event):
                    continue

                classifier_result = self._run_classification(event)

                test_result = TestResult(
                    idx,
                    original_event,
                    classifier_result[0] if classifier_result else False,
                    with_rules=self._testing_rules,
                    verbose=self._verbose
                )

                test_event.add_result(test_result)

                self._tested_rules.update(test_result.expected_rules)

                if not test_result:
                    continue

                if original_event.get('validate_schema_only'):
                    continue  # Do not run rules on events that are only for validation

                if self._type in {self.Types.RULES, self.Types.LIVE}:
                    alerts = self._run_rules_engine(classifier_result[0].sqs_messages)
                    test_result.alerts = alerts

                    if not original_event.get('skip_publishers'):
                        for alert in alerts:
                            publication_results = self._run_publishers(alert)
                            test_result.set_publication_results(publication_results)

                    if self._type == self.Types.LIVE:
                        for alert in alerts:
                            alert_result = self._run_alerting(alert)
                            test_result.add_live_test_result(alert.rule_name, alert_result)

            self._passed += test_event.passed
            self._failed += test_event.failed

            # It is possible for a test_event to have no results,
            # so only print it if it does and if quiet mode is no being used
            # Quite mode is overridden if not all of the events passed
            if test_event and not (self._quiet and test_event.all_passed):
                print(test_event)

        self._finalize()

        return self._failed == 0

    @staticmethod
    def _run_publishers(alert):
        """Runs publishers for all currently configured outputs on the given alert

        Args:
            - alert (Alert): The alert

        Returns:
            dict: A dict keyed by output:descriptor strings, mapped to nested dicts.
                  The nested dicts have 2 keys:
                  - publication (dict): The dict publication
                  - success (bool): True if the publishing finished, False if it errored.
        """
        configured_outputs = alert.outputs

        results = {}
        for configured_output in configured_outputs:
            [output_name, descriptor] = configured_output.split(':')

            try:
                output = MagicMock(spec=OutputDispatcher, __service__=output_name)
                results[configured_output] = {
                    'publication': compose_alert(alert, output, descriptor),
                    'success': True,
                }
            except (RuntimeError, TypeError, NameError) as err:
                results[configured_output] = {
                    'success': False,
                    'error': err,
                }
        return results

    def _get_test_files(self):
        """Helper to get rule files to be tested

        Yields:
            str: Path to test event file
        """
        files_filter = {
            os.path.splitext(name)[0] for name in self._files
        } if self._files else set()

        filtered = bool(files_filter)
        for root, _, test_event_files in os.walk(self._files_dir):
            for event_file in sorted(test_event_files):
                basename = os.path.splitext(event_file)[0]
                full_path = os.path.join(root, event_file)
                if not filtered or basename in files_filter:
                    yield full_path
                    if filtered:
                        files_filter.remove(basename)  # Remove this from the filter

        # Log any errors for filtered items that do not exist
        for basename in files_filter:
            self._append_error('No test event file found with base name \'{}\''.format(basename))

    def _setup_s3_mock(self, data):
        self._s3_mocker.return_value.Bucket.return_value.download_fileobj = (
            lambda k, d: d.write(json.dumps(data))
        )

    def _append_error(self, error, path=None, idx=None):
        key = 'error'
        if path:
            key = os.path.split(path)[1]
        key = key if not idx else '{}:{}'.format(key, idx)
        self._errors[key].append(error)

    def _load_test_file(self, path):
        """Helper to json load the contents of a file with some error handling

        Test files should be formatted as:

        [
            {
                "data": {},
                "description": "...",
                "...": "..."
            }
        ]

        Args:
            path (str): Relative path to file on disk

        Returns:
            dict: Loaded JSON from test event file
        """
        with open(path, 'r') as test_event_file:
            try:
                data = json.load(test_event_file)
            except (ValueError, TypeError):
                self._append_error('Test event file is not valid JSON', path=path)
                return

            if not isinstance(data, list):
                self._append_error('Test event file is improperly formatted', path=path)
                return

            for idx, event in enumerate(data):
                valid, record = self._format_test_record(event)
                if not valid:
                    self._append_error(record, path=path, idx=idx)
                    continue
                yield idx, event, record

    def _format_test_record(self, test_event):
        """Create a properly formatted Kinesis, S3, or SNS record.

        Supports a dictionary or string based data record.  Reads in
        event templates from the tests/integration/templates folder.

        Args:
            test_event (dict): Test event metadata dict with the following structure:
                data|override_record - string or dict of the raw data
                description - a string describing the test that is being performed
                trigger - bool of if the record should produce an alert
                source - which stream/s3 bucket originated the data
                service - which aws service originated the data
                compress (optional) - if the payload needs to be gzip compressed or not

        Returns:
            dict: in the format of the specific service
        """
        valid, error = self._validate_test_event(test_event)
        if not valid:
            return False, error

        self._apply_helpers(test_event)
        self._apply_defaults(test_event)

        data = test_event['data']
        if isinstance(data, dict):
            data = json.dumps(data)
        elif not isinstance(data, basestring):
            return False, 'Invalid data type: {}'.format(type(data))

        if test_event['service'] not in {'s3', 'kinesis', 'sns', 'stream_alert_app'}:
            return False, 'Unsupported service: {}'.format(test_event['service'])

        # Get a formatted record for this particular service
        return True, self._apply_service_template(
            test_event['service'],
            test_event['source'],
            data,
            test_event.get('compress', False)
        )

    def _apply_service_template(self, service, source, data, compress=False):
        """Provides a pre-configured template that reflects incoming payload from a service

        Args:
            service (str): The service for the payload template

        Returns:
            dict: Template of the payload for the given service
        """
        if service == 's3':
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
                        'arn': 'arn:aws:s3:::{}'.format(source),
                        'name': source,
                        'ownerIdentity': {
                            'principalId': 'EXAMPLE'
                        }
                    },
                    's3SchemaVersion': '1.0'
                },
                'responseElements': {
                    'x-amz-id-2': (
                        'EXAMPLE123/foo/bar'
                    ),
                    'x-amz-request-id': '...'
                },
                'awsRegion': 'us-east-1',
                'eventName': 'ObjectCreated:Put',
                'userIdentity': {
                    'principalId': 'EXAMPLE'
                },
                'eventSource': 'aws:s3'
            }

        elif service == 'kinesis':
            if compress:
                data = zlib.compress(data)

            kinesis_data = base64.b64encode(data)

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
                'eventSourceARN': 'arn:aws:kinesis:us-east-1:123456789012:stream/{}'.format(
                    source
                ),
                'eventSource': 'aws:kinesis',
                'awsRegion': 'us-east-1'
            }

        elif service == 'sns':
            return {
                'EventVersion': '1.0',
                'EventSubscriptionArn': 'arn:aws:sns:us-east-1:123456789012:{}'.format(source),
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
                    'TopicArn': 'arn:aws:sns:us-east-1:123456789012:{}'.format(source),
                    'Subject': '...'
                }
            }

        elif service == 'stream_alert_app':
            return {'stream_alert_app': source, 'logs': [data]}

    @staticmethod
    def _validate_test_event(test_event):
        """Check if the test event contains the required keys

        Args:
            test_event (dict): The loaded test event from json

        Returns:
            bool: True if the proper keys are present
        """
        required_keys = {'description', 'log', 'service', 'source'}

        test_event_keys = set(test_event)
        if not required_keys.issubset(test_event_keys):
            req_key_diff = required_keys.difference(test_event_keys)
            missing_keys = ', '.join('\'{}\''.format(key) for key in req_key_diff)
            return False, 'Missing required key(s) in test event: {}'.format(missing_keys)

        acceptable_data_keys = {'data', 'override_record'}
        if not test_event_keys & acceptable_data_keys:
            return False, 'Test event must contain either \'data\' or \'override_record\''

        optional_keys = {'compress', 'trigger_rules', 'validate_schema_only'}

        key_diff = test_event_keys.difference(required_keys | optional_keys | acceptable_data_keys)

        # Log a warning if there are extra keys declared in the test log
        if key_diff:
            extra_keys = ', '.join('\'{}\''.format(key) for key in key_diff)
            LOGGER.warning('Additional unnecessary keys in test event: %s', extra_keys)

        return True, None

    def _apply_defaults(self, test_event):
        """Apply default values to the given test event

        Args:
            test_event (dict): The loaded test event
        """
        if 'override_record' not in test_event:
            return

        event_log = self._config['logs'].get(test_event['log'])

        configuration = event_log.get('configuration', {})
        schema = configuration.get('envelope_keys', event_log['schema'])

        # Add apply default values based on the declared schema
        default_test_event = {
            key: ParserBase.default_optional_values(value)
            for key, value in schema.iteritems()
        }

        # Overwrite the fields included in the 'override_record' field,
        # and update the test event with a full 'data' key
        default_test_event.update(test_event['override_record'])
        test_event['data'] = default_test_event

    @staticmethod
    def _apply_helpers(test_record):
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

        def _find_and_apply_helpers(test_record):
            """Apply any helpers to the passed in test_record"""
            for key, value in test_record.iteritems():
                if isinstance(value, (str, unicode)):
                    test_record[key] = re.sub(
                        helper_regex,
                        lambda match: record_helpers[match.group('helper')](),
                        value
                    )
                elif isinstance(value, dict):
                    _find_and_apply_helpers(test_record[key])

        _find_and_apply_helpers(test_record)

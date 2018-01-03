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
# pylint: disable=protected-access,attribute-defined-outside-init
import base64
import json
import logging

from mock import call, patch
from moto import mock_kinesis
from nose.tools import (
    assert_equal,
    assert_false,
    assert_list_equal,
    assert_true
)
import boto3

from stream_alert.rule_processor import LOGGER
from stream_alert.rule_processor.handler import load_config, StreamAlert
from stream_alert.rule_processor.rules_engine import StreamRules
from stream_alert.rule_processor.threat_intel import StreamThreatIntel
from tests.unit.stream_alert_rule_processor.test_helpers import (
    convert_events_to_kinesis,
    get_mock_context,
    get_valid_event,
    make_kinesis_raw_record,
)

rule = StreamRules.rule


class TestStreamAlert(object):
    """Test class for StreamAlert class"""

    @patch('stream_alert.rule_processor.handler.load_config',
           lambda: load_config('tests/unit/conf/'))
    def setup(self):
        """Setup before each method"""
        self.__sa_handler = StreamAlert(get_mock_context(), False)

    def test_run_no_records(self):
        """StreamAlert Class - Run, No Records"""
        passed = self.__sa_handler.run({'Records': []})
        assert_false(passed)

    def test_get_alerts(self):
        """StreamAlert Class - Get Alerts"""
        default_list = ['alert1', 'alert2']
        self.__sa_handler._alerts = default_list

        assert_list_equal(self.__sa_handler.get_alerts(), default_list)

    @patch('stream_alert.rule_processor.handler.StreamClassifier.load_sources')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_no_sources(self, extract_mock, load_sources_mock):
        """StreamAlert Class - Run, No Loaded Sources"""
        extract_mock.return_value = ('lambda', 'entity')
        load_sources_mock.return_value = None

        self.__sa_handler.run({'Records': ['record']})

        load_sources_mock.assert_called_with('lambda', 'entity')

    @patch('logging.Logger.error')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_bad_service(self, extract_mock, log_mock):
        """StreamAlert Class - Run, Bad Service"""
        extract_mock.return_value = ('', 'entity')

        self.__sa_handler.run({'Records': ['record']})

        log_mock.assert_called_with('No valid service found in payload\'s raw record. '
                                    'Skipping record: %s', 'record')

    @patch('logging.Logger.error')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_bad_entity(self, extract_mock, log_mock):
        """StreamAlert Class - Run, Bad Entity"""
        extract_mock.return_value = ('kinesis', '')

        self.__sa_handler.run({'Records': ['record']})

        log_mock.assert_called_with(
            'Unable to extract entity from payload\'s raw record for '
            'service %s. Skipping record: %s', 'kinesis', 'record')

    @patch('stream_alert.rule_processor.handler.load_stream_payload')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.load_sources')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_load_payload_bad(
            self,
            extract_mock,
            load_sources_mock,
            load_payload_mock):
        """StreamAlert Class - Run, Loaded Payload Fail"""
        extract_mock.return_value = ('lambda', 'entity')
        load_sources_mock.return_value = True

        self.__sa_handler.run({'Records': ['record']})

        load_payload_mock.assert_called_with(
            'lambda',
            'entity',
            'record'
        )

    @patch('stream_alert.rule_processor.handler.StreamRules.process')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_with_alert(self, extract_mock, rules_mock):
        """StreamAlert Class - Run, With Alert"""
        extract_mock.return_value = ('kinesis', 'unit_test_default_stream')
        rules_mock.return_value = (['success!!'], ['normalized_records'])

        passed = self.__sa_handler.run(get_valid_event())

        assert_true(passed)

    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_alert_count(self, extract_mock):
        """StreamAlert Class - Run, Check Count With 4 Logs"""
        count = 4
        extract_mock.return_value = ('kinesis', 'unit_test_default_stream')
        self.__sa_handler.run(get_valid_event(count))
        assert_equal(self.__sa_handler._processed_record_count, count)

    @patch('logging.Logger.debug')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_no_alerts(self, extract_mock, log_mock):
        """StreamAlert Class - Run, With No Alerts"""
        extract_mock.return_value = ('kinesis', 'unit_test_default_stream')
        self.__sa_handler.run(get_valid_event())

        calls = [call('Processed %d valid record(s) that resulted in %d alert(s).', 1, 0),
                 call('Invalid record count: %d', 0),
                 call('%s alerts triggered', 0)]

        log_mock.assert_has_calls(calls)

    @patch('logging.Logger.error')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_invalid_data(self, extract_mock, log_mock):
        """StreamAlert Class - Run, Invalid Data"""
        extract_mock.return_value = ('kinesis', 'unit_test_default_stream')
        event = get_valid_event()

        # Replace the good log data with bad data
        event['Records'][0]['kinesis']['data'] = base64.b64encode('{"bad": "data"}')

        # Swap out the alias so the logging occurs
        self.__sa_handler.env['lambda_alias'] = 'production'
        self.__sa_handler.run(event)

        assert_equal(
            log_mock.call_args[0][0],
            'Record does not match any defined schemas: %s\n%s')
        assert_equal(log_mock.call_args[0][2], '{"bad": "data"}')

    @patch('stream_alert.rule_processor.sink.StreamSink.sink')
    @patch('stream_alert.rule_processor.handler.StreamRules.process')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_send_alerts(self, extract_mock, rules_mock, sink_mock):
        """StreamAlert Class - Run, Send Alert"""
        extract_mock.return_value = ('kinesis', 'unit_test_default_stream')
        rules_mock.return_value = (['success!!'], ['normalized_records'])

        # Set send_alerts to true so the sink happens
        self.__sa_handler.enable_alert_processor = True

        # Swap out the alias so the logging occurs
        self.__sa_handler.env['lambda_alias'] = 'production'

        self.__sa_handler.run(get_valid_event())

        sink_mock.assert_called_with(['success!!'])

    @patch('logging.Logger.debug')
    @patch('stream_alert.rule_processor.handler.StreamRules.process')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_debug_log_alert(self, extract_mock, rules_mock, log_mock):
        """StreamAlert Class - Run, Debug Log Alert"""
        extract_mock.return_value = ('kinesis', 'unit_test_default_stream')
        rules_mock.return_value = (['success!!'], ['normalized_records'])

        # Cache the logger level
        log_level = LOGGER.getEffectiveLevel()

        # Increase the logger level to debug
        LOGGER.setLevel(logging.DEBUG)

        self.__sa_handler.run(get_valid_event())

        # Reset the logger level
        LOGGER.setLevel(log_level)

        log_mock.assert_called_with('Alerts:\n%s', '[\n  "success!!"\n]')

    @patch('stream_alert.rule_processor.handler.load_stream_payload')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.load_sources')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_no_payload_class(
            self,
            extract_mock,
            load_sources_mock,
            load_payload_mock):
        """StreamAlert Class - Run, No Payload Class"""
        extract_mock.return_value = ('blah', 'entity')
        load_sources_mock.return_value = True
        load_payload_mock.return_value = None

        self.__sa_handler.run({'Records': ['record']})

        load_payload_mock.assert_called()

    @mock_kinesis
    def test_firehose_record_delivery_disabled_logs(self):
        """StreamAlert Class - Firehose Record Delivery - Disabled Logs"""
        self.__sa_handler.firehose_client = boto3.client(
            'firehose', region_name='us-east-1')

        test_event = convert_events_to_kinesis([
            # unit_test_simple_log
            {'unit_key_01': 2, 'unit_key_02': 'testtest'}
            for _
            in range(10)])

        delivery_stream_names = ['streamalert_data_unit_test_simple_log']

        # Setup mock delivery streams
        for delivery_stream in delivery_stream_names:
            self.__sa_handler.firehose_client.create_delivery_stream(
                DeliveryStreamName=delivery_stream,
                S3DestinationConfiguration={
                    'RoleARN': 'arn:aws:iam::123456789012:role/firehose_delivery_role',
                    'BucketARN': 'arn:aws:s3:::kinesis-test',
                    'Prefix': '{}/'.format(delivery_stream),
                    'BufferingHints': {
                        'SizeInMBs': 123,
                        'IntervalInSeconds': 124
                    },
                    'CompressionFormat': 'Snappy',
                }
            )

        with patch.object(self.__sa_handler.firehose_client, 'put_record_batch') as firehose_mock:
            firehose_mock.return_value = {'FailedPutCount': 0}

            self.__sa_handler.config['global']['infrastructure']['firehose'] = {
                'disabled_logs': ['unit_test_simple_log']}
            self.__sa_handler.run(test_event)

            firehose_mock.assert_not_called()

    @patch('stream_alert.rule_processor.threat_intel.StreamThreatIntel._query')
    @patch('stream_alert.rule_processor.threat_intel.StreamThreatIntel.load_from_config')
    def test_run_threat_intel_enabled(self, mock_threat_intel, mock_query): # pylint: disable=no-self-use
        """StreamAlert Class - Run SA when threat intel enabled"""
        @rule(datatypes=['sourceAddress'], outputs=['s3:sample_bucket'])
        def match_ipaddress(_): # pylint: disable=unused-variable
            """Testing dummy rule"""
            return True

        mock_threat_intel.return_value = StreamThreatIntel('test_table_name', 'us-east-1')
        mock_query.return_value = ([], [])

        sa_handler = StreamAlert(get_mock_context(), False)
        event = {
            'account': 123456,
            'region': '123456123456',
            'source': '1.1.1.2',
            'detail': {
                'eventName': 'ConsoleLogin',
                'sourceIPAddress': '1.1.1.2',
                'recipientAccountId': '654321'
            }
        }
        events = []
        for i in range(10):
            event['source'] = '1.1.1.{}'.format(i)
            events.append(event)

        kinesis_events = {
            'Records': [make_kinesis_raw_record('test_kinesis_stream', json.dumps(event))
                        for event in events]
        }

        passed = sa_handler.run(kinesis_events)
        assert_true(passed)

        assert_equal(mock_query.call_count, 1)

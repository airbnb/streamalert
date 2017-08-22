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
import logging

from mock import call, Mock, mock_open, patch
from multiprocessing import Manager

from nose.tools import (
    assert_equal,
    assert_false,
    assert_list_equal,
    assert_true,
    raises
)

from stream_alert.rule_processor import LOGGER
from stream_alert.rule_processor.config import ConfigError
from stream_alert.rule_processor.handler import StreamAlert
from stream_alert.rule_processor.handler import load_config


from unit.stream_alert_rule_processor.test_helpers import (
    MultiprocProcessMock,
    _get_mock_context,
    _get_valid_event
)


@patch('stream_alert.rule_processor.handler.Metrics.send_metrics', Mock())
class TestStreamAlert(object):
    """Test class for StreamAlert class"""

    def __init__(self):
        self.__sa_handler = None

    @patch('stream_alert.rule_processor.handler.load_config',
           lambda: load_config('test/unit/conf/'))
    def setup(self):
        """Setup before each method"""
        self.__sa_handler = StreamAlert(_get_mock_context(), False)

    def test_run_no_records(self):
        """StreamAlert Class - Run, No Records"""
        passed = self.__sa_handler.run({'Records': []})
        assert_false(passed)

    @staticmethod
    @raises(ConfigError)
    def test_run_config_error(_):
        """StreamAlert Class - Run, Config Error"""
        mock = mock_open(read_data='non-json string that will raise an exception')
        with patch('__builtin__.open', mock):
            StreamAlert(_get_mock_context())

    def test_get_alerts(self):
        """StreamAlert Class - Get Alerts"""
        default_list = ['alert1', 'alert2']
        proxy_list = Manager().list()
        proxy_list.extend(default_list)
        self.__sa_handler._alerts = proxy_list

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

        log_mock.assert_called_with('Unable to extract entity from payload\'s raw record for '
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
            'record',
            self.__sa_handler.metrics
        )

    @patch('stream_alert.rule_processor.handler.StreamRules.process')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_with_alert(self, extract_mock, rules_mock):
        """StreamAlert Class - Run, With Alert"""
        extract_mock.return_value = ('kinesis', 'unit_test_default_stream')
        rules_mock.return_value = ['success!!']

        passed = self.__sa_handler.run(_get_valid_event())

        assert_true(passed)

    @patch('logging.Logger.debug')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_no_alerts(self, extract_mock, log_mock):
        """StreamAlert Class - Run, With No Alerts"""
        extract_mock.return_value = ('kinesis', 'unit_test_default_stream')
        self.__sa_handler.run(_get_valid_event())

        calls = [call('Running worker #%d for %d-%d of %d records', 1, 1, 1, 1),
                 call('Number of running workers: %d', 1)]

        log_mock.assert_has_calls(calls)

    @patch('stream_alert.rule_processor.handler.multiproc.Process', MultiprocProcessMock)
    @patch('logging.Logger.error')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_invalid_data(self, extract_mock, log_mock):
        """StreamAlert Class - Run, Invalid Data"""
        extract_mock.return_value = ('kinesis', 'unit_test_default_stream')
        event = _get_valid_event()

        # Replace the good log data with bad data
        event['Records'][0]['kinesis']['data'] = base64.b64encode('{"bad": "data"}')

        # Swap out the alias so the logging occurs
        self.__sa_handler.env['lambda_alias'] = 'production'
        self.__sa_handler.run(event)

        assert_equal(log_mock.call_args[0][0], 'Record does not match any defined schemas: %s\n%s')
        assert_equal(log_mock.call_args[0][2], '{"bad": "data"}')

    @patch('stream_alert.rule_processor.handler.multiproc.Process', MultiprocProcessMock)
    @patch('stream_alert.rule_processor.sink.StreamSink.sink')
    @patch('stream_alert.rule_processor.handler.StreamRules.process')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_send_alerts(self, extract_mock, rules_mock, sink_mock):
        """StreamAlert Class - Run, Send Alert"""
        extract_mock.return_value = ('kinesis', 'unit_test_default_stream')
        rules_mock.return_value = ['success!!']

        # Set send_alerts to true so the sink happens
        self.__sa_handler.enable_alert_processor = True

        # Swap out the alias so the logging occurs
        self.__sa_handler.env['lambda_alias'] = 'production'

        self.__sa_handler.run(_get_valid_event())

        sink_mock.assert_called_with(['success!!'])

    @patch('logging.Logger.debug')
    @patch('stream_alert.shared.metrics.Metrics.send_metrics')
    @patch('stream_alert.rule_processor.handler.StreamRules.process')
    @patch('stream_alert.rule_processor.handler.StreamClassifier.extract_service_and_entity')
    def test_run_debug_log_alert(self, extract_mock, rules_mock, _, log_mock):
        """StreamAlert Class - Run, Debug Log Alert"""
        extract_mock.return_value = ('kinesis', 'unit_test_default_stream')
        rules_mock.return_value = ['success!!']

        # Cache the logger level
        log_level = LOGGER.getEffectiveLevel()

        # Increase the logger level to debug
        LOGGER.setLevel(logging.DEBUG)

        self.__sa_handler.run(_get_valid_event())

        # Reset the logger level
        LOGGER.setLevel(log_level)

        log_mock.assert_called_with('Alerts:\n%s', '[\n  "success!!"\n]')

    @patch('stream_alert.rule_processor.handler.copy')
    @patch('stream_alert.rule_processor.handler.multiproc.Process')
    @patch('stream_alert.rule_processor.payload.StreamPayload')
    @patch('stream_alert.rule_processor.handler.multiproc.cpu_count')
    @patch('stream_alert.rule_processor.handler.PROC_MANAGER')
    def test_record_grouping(
            self,
            mp_manager_mock,
            mp_cpu_mock,
            payload_mock,
            process_mock,
            copy_mock):
        """StreamAlert Class - Record Grouping for Multiprocessing"""
        # Set the cpu_count return value to a predetermined value
        mp_cpu_mock.return_value = 2
        # Disable the actual creation of a mutex
        mp_manager_mock.Lock.return_value = None
        # Create a list of predetermined values to compare against
        payload_mock.pre_parse.return_value = range(22)
        # Force copy to return the actual object instead of a copy
        copy_mock.return_value = self.__sa_handler.classifier

        self.__sa_handler._run_batches(payload_mock, [])

        # Set the groups we expect to be created from the segmentation logic
        groups = [[0, 1, 2, 3, 4, 5],
                  [6, 7, 8, 9, 10, 11],
                  [12, 13, 14, 15, 16, 17],
                  [18, 19, 20, 21]]

        # Create all of the calls we expect to be found
        call_01 = call(args=(self.__sa_handler.classifier, groups[0], None),
                       target=self.__sa_handler._process_alerts)
        call_02 = call(args=(self.__sa_handler.classifier, groups[1], None),
                       target=self.__sa_handler._process_alerts)
        call_03 = call(args=(self.__sa_handler.classifier, groups[2], None),
                       target=self.__sa_handler._process_alerts)
        call_04 = call(args=(self.__sa_handler.classifier, groups[3], None),
                       target=self.__sa_handler._process_alerts)

        all_calls = [call_01, call_01.start(), call_02, call_02.start(),
                     call_03, call_03.start(), call_04, call_04.start()]

        # Check that the calls exist
        process_mock.assert_has_calls(all_calls)

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

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
import os
from collections import OrderedDict
from unittest.mock import Mock, patch

import pytest

import streamalert.classifier.classifier as classifier_module
from streamalert.classifier.classifier import Classifier
from streamalert.shared.exceptions import ConfigError


class TestClassifier:
    """Classifier tests"""
    # pylint: disable=protected-access,no-self-use,attribute-defined-outside-init

    _service_name = 'service_name'
    _resource_name = 'resource_name'

    def setup(self):
        """Classifier - Setup"""
        with patch.object(classifier_module, 'Normalizer'), \
            patch.object(classifier_module, 'FirehoseClient'), \
            patch.object(classifier_module, 'SQSClient'), \
            patch.dict(os.environ, {'CLUSTER': 'prod'}), \
            patch('streamalert.classifier.classifier.config.load_config',
                  Mock(return_value=self._mock_conf())):
            self._classifier = Classifier()

    def teardown(self):
        """Classifier - Teardown"""
        Classifier._config = None
        Classifier._firehose_client = None

    @classmethod
    def _mock_conf(cls):
        return {
            'logs': cls._mock_logs(),
            'clusters': {'prod': {'data_sources': cls._mock_sources()}},
            'global': cls._mock_global()
        }

    @classmethod
    def _mock_sources(cls):
        return {
            cls._service_name: {
                cls._resource_name: [
                    'log_type_01'
                ]
            }
        }

    @classmethod
    def _mock_logs(cls):
        return OrderedDict([
            ('log_type_01:sub_type', OrderedDict([
                ('parser', 'json'),
                ('schema', OrderedDict([
                    ('type_01_key_01', 'string'),
                    ('type_01_key_02', 'integer'),
                    ('type_01_key_03', 'boolean')
                ]))
            ])),
            ('log_type_02:sub_type', OrderedDict([
                ('parser', 'json'),
                ('schema', OrderedDict([
                    ('type_02_key_01', 'string'),
                    ('type_02_key_02', 'integer'),
                    ('type_02_key_03', 'boolean')
                ]))
            ]))
        ])

    @classmethod
    def _mock_global(cls):
        return {
            'account': {
                'prefix': 'unit-test'
            },
            'infrastructure': {
                'firehose': {
                    'enabled': True,
                    'enabled_logs': {
                        'log_type_01': None
                    }
                }
            }
        }

    @classmethod
    def _mock_payload(cls, records):
        return Mock(
            service=lambda: cls._service_name,
            resource=cls._resource_name,
            pre_parse=lambda: records
        )

    @classmethod
    def _mock_payload_record(cls):
        return Mock(data={'key': 'value'},
                    parsed_records=[{f'key_{i}': 'value'} for i in range(2)],
                    invalid_records=[{f'key_{i}': 'value'} for i in range(1)],
                    log_schema_type='foo:bar',
                    log_type='foo',
                    __nonzero__=lambda s: True,
                    __len__=lambda s: 10,
                    parser=None)

    @classmethod
    def _mock_parser(cls, parse_result):
        return Mock(
            return_value=Mock(
                parse=Mock(side_effect=parse_result)
            )
        )

    def test_config_property(self):
        """Classifier - Config Property"""
        assert self._classifier._config == self._mock_conf()

    def test_classified_payloads(self):
        """Classifier - Classified Payloads Property"""
        assert self._classifier.classified_payloads == []

    def test_data_retention_enabled(self):
        """Classifier - Data Retention Enabled Property"""
        assert self._classifier.data_retention_enabled

    def test_load_logs_for_resource(self):
        """Classifier - Load Logs for Resource"""
        expected_result = OrderedDict([
            ('log_type_01:sub_type', OrderedDict([
                ('parser', 'json'),
                ('schema', OrderedDict([
                    ('type_01_key_01', 'string'),
                    ('type_01_key_02', 'integer'),
                    ('type_01_key_03', 'boolean')
                ]))
            ]))
        ])

        result = self._classifier._load_logs_for_resource(self._service_name, self._resource_name)
        assert result == expected_result

    def test_load_logs_for_resource_invalid_service(self):
        """Classifier - Load Logs for Resource, Invalid Service"""
        pytest.raises(
            ConfigError,
            self._classifier._load_logs_for_resource,
            'invalid_service',
            self._resource_name
        )

    def test_load_logs_for_resource_invalid_resource(self):
        """Classifier - Load Logs for Resource, Invalid Resource"""
        pytest.raises(
            ConfigError,
            self._classifier._load_logs_for_resource,
            self._service_name,
            'invalid_resource'
        )

    @patch.object(classifier_module, 'get_parser')
    def test_process_log_schemas(self, parse_mock):
        """Classifier - Process Log Schemas"""
        logs_config = self._mock_logs()
        payload_record = self._mock_payload_record()
        mock_parser = self._mock_parser([True])
        expected_log_type = 'log_type_01:sub_type'
        parse_mock.return_value = mock_parser

        result = Classifier._process_log_schemas(payload_record, logs_config)
        assert result
        mock_parser.assert_called_with(
            logs_config[expected_log_type], log_type=expected_log_type
        )
        assert payload_record.parser == mock_parser()

    @patch('logging.Logger.debug')
    @patch.object(classifier_module, 'get_parser')
    def test_process_log_schemas_multiple(self, parse_mock, log_mock):
        """Classifier - Process Log Schemas, Multiple Calls"""
        logs_config = self._mock_logs()
        payload_record = self._mock_payload_record()
        mock_parser = self._mock_parser([False, True])
        expected_log_type = 'log_type_02:sub_type'
        parse_mock.return_value = mock_parser

        result = Classifier._process_log_schemas(payload_record, logs_config)
        assert result
        mock_parser.assert_called_with(
            logs_config[expected_log_type], log_type=expected_log_type
        )
        assert payload_record.parser == mock_parser()
        log_mock.assert_any_call(
            'Failed to classify data with schema: %s', 'log_type_01:sub_type'
        )

    @patch('logging.Logger.debug')
    @patch.object(classifier_module, 'get_parser')
    def test_process_log_schemas_failure(self, parse_mock, log_mock):
        """Classifier - Process Log Schemas, Failure"""
        logs_config = self._mock_logs()
        payload_record = self._mock_payload_record()
        mock_parser = self._mock_parser([False, False])
        parse_mock.return_value = mock_parser

        result = Classifier._process_log_schemas(payload_record, logs_config)
        assert result == False
        assert payload_record.parser is None
        log_mock.assert_any_call(
            'Failed to classify data with schema: %s', 'log_type_01:sub_type'
        )
        log_mock.assert_any_call(
            'Failed to classify data with schema: %s', 'log_type_02:sub_type'
        )

    @patch.object(Classifier, '_process_log_schemas')
    def test_classify_payload(self, process_mock):
        """Classifier - Classify Payload"""
        with patch.object(classifier_module, 'Normalizer') as normalizer_mock, \
                patch.object(Classifier, '_log_bad_records') as log_mock:

            payload_record = self._mock_payload_record()
            self._classifier._classify_payload(self._mock_payload([payload_record]))
            process_mock.assert_called_with(
                payload_record,
                OrderedDict([
                    ('log_type_01:sub_type', self._mock_logs()['log_type_01:sub_type'])
                ])
            )
            normalizer_mock.normalize.assert_called_with(
                payload_record.parsed_records[-1], 'foo:bar'
            )
            assert self._classifier._payloads == [payload_record]
            log_mock.assert_called_with(payload_record, 1)

    @patch('logging.Logger.error')
    def test_classify_payload_no_logs(self, log_mock):
        """Classifier - Classify Payload, Log Logs Config"""
        with patch.object(Classifier, '_load_logs_for_resource') as log_resource_mock:
            log_resource_mock.return_value = {}
            self._classifier._classify_payload(self._mock_payload([self._mock_payload_record()]))

            log_resource_mock.assert_called_with(self._service_name, self._resource_name)
            log_mock.assert_called_with(
                'No log types defined for resource [%s] in sources configuration for service [%s]',
                self._resource_name,
                self._service_name
            )

    # Since we mock the Normalizer, we must also mock the class variable
    # referenced in the class methods.
    @patch('streamalert.shared.normalize.Normalizer._types_config', {})
    def test_classify_payload_bad_record(self):
        """Classifier - Classify Payload, Bad Record"""
        with patch.object(Classifier, '_process_log_schemas'), \
                patch.object(Classifier, '_log_bad_records') as log_mock:

            payload_record = self._mock_payload_record()
            payload_record.__nonzero__ = lambda s: False
            self._classifier._classify_payload(self._mock_payload([payload_record]))
            log_mock.assert_called_with(payload_record, 1)

    def test_log_bad_records(self):
        """Classifier - Log Bad Records"""
        self._classifier._log_bad_records(None, 2)
        assert self._classifier._failed_record_count == 2

    def test_log_bad_records_zero(self):
        """Classifier - Log Bad Records, None"""
        self._classifier._log_bad_records(None, 0)
        assert self._classifier._failed_record_count == 0

    @patch.object(classifier_module.MetricLogger, 'log_metric')
    def test_log_metrics(self, metric_mock):
        """Classifier - Log Metrics"""
        payload_record = self._mock_payload_record()
        self._classifier._payloads = [
            payload_record
        ]
        self._classifier._processed_size = 10
        self._classifier._failed_record_count = 10
        self._classifier._log_metrics()

        metric_mock.assert_any_call('classifier', 'TotalRecords', 2)
        metric_mock.assert_any_call('classifier', 'TotalProcessedSize', 10)
        metric_mock.assert_any_call('classifier', 'FailedParses', 10)

    @patch.object(Classifier, '_classify_payload')
    def test_run(self, classifiy_mock):
        """Classifier - Run"""
        with patch.object(classifier_module.StreamPayload, 'load_from_raw_record') as load_mock:
            payload = self._mock_payload([self._mock_payload_record()])
            load_mock.return_value = payload
            self._classifier.run([Mock()])
            classifiy_mock.assert_called_with(payload)

    @patch('logging.Logger.debug')
    def test_run_no_records(self, log_mock):
        """Classifier - Run, No Records"""
        self._classifier.run([])
        log_mock.assert_called_with('Number of incoming records: %d', 0)

    @patch.object(Classifier, '_classify_payload')
    def test_run_no_payloads(self, classifiy_mock):
        """Classifier - Run, No Payloads"""
        with patch.object(classifier_module.StreamPayload, 'load_from_raw_record') as load_mock:
            load_mock.return_value = False
            self._classifier.run([Mock()])
            classifiy_mock.assert_not_called()

    @patch('streamalert.shared.artifact_extractor.ArtifactExtractor.run')
    @patch.object(Classifier, '_classify_payload')
    def test_run_artifact_extractor_disabled(self, classifiy_mock, artifact_extractor_mock):
        """Classifier - Test run method when artifact_extractor disabled"""
        with patch.object(classifier_module.StreamPayload, 'load_from_raw_record') as load_mock:
            payload = self._mock_payload([self._mock_payload_record()])
            load_mock.return_value = payload
            self._classifier.run([Mock()])
            classifiy_mock.assert_called_with(payload)
            artifact_extractor_mock.assert_not_called()

    @patch('streamalert.shared.artifact_extractor.ArtifactExtractor.run')
    @patch.object(Classifier, '_classify_payload')
    def test_run_artifact_extractor_enabled(self, classifiy_mock, artifact_extractor_mock):
        """Classifier - Test run method when artifact_extractor enabled"""
        Classifier._config['global']['infrastructure']['artifact_extractor'] = {
            'enabled': True,
            'firehose_buffer_size': 128,
            'firehose_buffer_interval': 60
        }
        with patch.object(classifier_module.StreamPayload, 'load_from_raw_record') as load_mock:
            payload = self._mock_payload([self._mock_payload_record()])
            load_mock.return_value = payload
            self._classifier.run([Mock()])
            classifiy_mock.assert_called_with(payload)
            artifact_extractor_mock.assert_called_once()

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
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError

from streamalert.shared.firehose import FirehoseClient


class TestFirehoseClient:
    """Test class for FirehoseClient"""
    # pylint: disable=protected-access,no-self-use,attribute-defined-outside-init

    def setup(self):
        """Setup before each method"""
        with patch('boto3.client'):  # patch to speed up unit tests slightly
            self._client = FirehoseClient(
                prefix='unit-test',
                firehose_config={'use_prefix': True}
            )

    def teardown(self):
        """Teardown after each method"""
        FirehoseClient._ENABLED_LOGS.clear()

    @property
    def _sample_payloads(self):
        return [
            Mock(
                log_schema_type='log_type_01_sub_type_01',
                parsed_records=[
                    {
                        'unit_key_01': 1,
                        'unit_key_02': 'test'
                    },
                    {
                        'unit_key_01': 2,
                        'unit_key_02': 'test'
                    }
                ]
            ),
            Mock(
                log_schema_type='log_type_02_sub_type_01',
                parsed_records=[
                    {
                        'date': 'January 01, 3005',
                        'unixtime': '32661446400',
                        'host': 'my-host.name.website.com',
                        'data': {
                            'super': 'secret'
                        }
                    }
                ]
            )
        ]

    @classmethod
    def _sample_raw_records(cls, count=2):
        return [{f'key_{i}': f'value_{i}'} for i in range(count)]

    def test_records_to_json_list(self):
        """FirehoseClient - Records JSON Lines"""
        records = self._sample_raw_records()

        expected_result = [
            '{"key_0":"value_0"}\n',
            '{"key_1":"value_1"}\n'
        ]

        result = FirehoseClient._records_to_json_list(records)
        assert result == expected_result

    def test_record_batches(self):
        """FirehoseClient - Record Batches"""
        records = self._sample_raw_records()

        expected_result = [
            [
                '{"key_0":"value_0"}\n',
                '{"key_1":"value_1"}\n'
            ]
        ]

        result = list(FirehoseClient._record_batches(records, 'test_function_name'))
        assert result == expected_result

    @patch.object(FirehoseClient, '_log_failed')
    def test_record_batches_rec_too_large(self, failure_mock):
        """FirehoseClient - Record Batches, Record Too Large"""
        records = [
            {'key': 'test' * 1000 * 1000}
        ]

        result = list(FirehoseClient._record_batches(records, 'test_function_name'))
        assert not result
        failure_mock.assert_called_with(1, 'test_function_name')

    def test_record_batches_max_batch_count(self):
        """FirehoseClient - Record Batches, Max Batch Count"""
        records = self._sample_raw_records(count=501)

        result = list(FirehoseClient._record_batches(records, 'test_function_name'))
        assert len(result) == 2
        assert len(result[0]) == 500
        assert len(result[1]) == 1

    def test_record_batches_max_batch_size(self):
        """FirehoseClient - Record Batches, Max Batch Size"""
        records = [{f'key_{i}': 'test' * 100000} for i in range(10)]
        result = list(FirehoseClient._record_batches(records, 'test_function_name'))
        assert len(result) == 2
        assert len(result[0]) == 9
        assert len(result[1]) == 1
        batch_size_01 = sum(len(rec) for rec in result[0])
        batch_size_02 = sum(len(rec) for rec in result[1])
        assert batch_size_01 < FirehoseClient.MAX_BATCH_SIZE
        assert batch_size_02 < FirehoseClient.MAX_BATCH_SIZE
        assert batch_size_01 + batch_size_02 > FirehoseClient.MAX_BATCH_SIZE

    def test_sanitize_keys(self):
        """FirehoseClient - Sanitize Keys"""
        test_event = {
            'date': 'January 01, 3005',
            'data': {
                'super-duper': 'secret',
                'do_not_sanitize_me': 1,
                'example-key': 2,
                'moar**data': 3,
                'even.more': 4
            }
        }

        expected_sanitized_event = {
            'date': 'January 01, 3005',
            'data': {
                'super_duper': 'secret',
                'do_not_sanitize_me': 1,
                'example_key': 2,
                'moar__data': 3,
                'even_more': 4
            }
        }

        sanitized_event = FirehoseClient.sanitize_keys(test_event)
        assert sanitized_event == expected_sanitized_event

    def test_strip_successful_records(self):
        """FirehoseClient - Strip Successful Records"""
        batch = [{'test': 'success'}, {'other': 'failure'}, {'other': 'info'}]
        response = {
            'FailedPutCount': 1,
            'RequestResponses': [
                {'RecordId': 'rec_id_01'},
                {'ErrorCode': 10, 'ErrorMessage': 'foo'},
                {'RecordId': 'rec_id_03'}
            ]
        }

        expected_batch = [{'other': 'failure'}]
        FirehoseClient._strip_successful_records(batch, response)

        assert batch == expected_batch

    def test_categorize_records(self):
        """FirehoseClient - Categorize Records"""
        FirehoseClient._ENABLED_LOGS = {
            'log_type_01_sub_type_01': 'log_type_01:sub_type_01',
            'log_type_02_sub_type_01': 'log_type_02:sub_type_01'
        }

        payloads = self._sample_payloads

        result = self._client._categorize_records(payloads)
        expected_result = {
            'log_type_01_sub_type_01': payloads[0].parsed_records,
            'log_type_02_sub_type_01': payloads[1].parsed_records
        }
        assert dict(result) == expected_result

    def test_categorize_records_none_enabled(self):
        """FirehoseClient - Categorize Records, None Enabled"""
        payloads = self._sample_payloads
        result = self._client._categorize_records(payloads)

        assert not dict(result)

    def test_categorize_records_subset_enabled(self):
        """FirehoseClient - Categorize Records, Subset Enabled"""
        FirehoseClient._ENABLED_LOGS = {
            'log_type_01_sub_type_01': 'log_type_01:sub_type_01'
        }

        payloads = self._sample_payloads

        result = self._client._categorize_records(payloads)
        expected_result = {
            'log_type_01_sub_type_01': payloads[0].parsed_records
        }
        assert dict(result) == expected_result

    @patch.object(FirehoseClient, '_log_failed')
    def test_finalize_failures(self, failure_mock):
        """FirehoseClient - Finalize, With Failures"""
        response = {
            'FailedPutCount': 1,
            'RequestResponses': [
                {'RecordId': 'rec_id_01'},
                {'ErrorCode': 10, 'ErrorMessage': 'foo'},
                {'RecordId': 'rec_id_03'}
            ]
        }

        FirehoseClient._finalize(response, 'stream_name', 3, 'test_function_name')
        failure_mock.assert_called_with(1, 'test_function_name')

    @patch('logging.Logger.info')
    def test_finalize_success(self, log_mock):
        """FirehoseClient - Finalize, Success"""
        request_id = 'success_id'
        stream_name = 'stream_name'
        count = 3
        response = {
            'ResponseMetadata': {
                'RequestId': request_id
            }
        }

        FirehoseClient._finalize(response, stream_name, count, 'test_function_name')
        log_mock.assert_called_with(
            'Successfully sent %d message(s) to firehose %s with RequestId \'%s\'',
            count,
            stream_name,
            request_id
        )

    def test_send_batch(self):
        """FirehoseClient - Send Batch"""
        records = [
            '{"unit_key_02":"test","unit_key_01":1}\n',
            '{"unit_key_02":"test","unit_key_01":2}\n'
        ]

        stream_name = 'test_stream_name'
        expected_second_call = [
            {'Data': records[1]}
        ]
        with patch.object(self._client, '_client') as boto_mock:
            boto_mock.put_record_batch.side_effect = [
                {
                    'FailedPutCount': 1,
                    'RequestResponses': [
                        {'RecordId': 'rec_id_01'},
                        {'ErrorCode': 10, 'ErrorMessage': 'foo'}
                    ]
                },
                {
                    'FailedPutCount': 0,
                    'RequestResponses': [
                        {'RecordId': 'rec_id_02'},
                    ]
                }
            ]

            self._client._send_batch(stream_name, records, 'test_function_name')

            boto_mock.put_record_batch.assert_called_with(
                DeliveryStreamName=stream_name,
                Records=expected_second_call
            )

    @patch('logging.Logger.exception')
    @patch.object(FirehoseClient, 'MAX_BACKOFF_ATTEMPTS', 1)
    def test_send_batch_error(self, log_mock):
        """FirehoseClient - Send Batch, Error"""
        stream_name = 'test_stream_name'
        with patch.object(self._client, '_client') as boto_mock:
            error = ClientError({'Error': {'Code': 10}}, 'InvalidRequestException')
            boto_mock.put_record_batch.side_effect = error

            self._client._send_batch(stream_name, ['data'], 'test_function_name')

            log_mock.assert_called_with('Firehose request failed')

    def test_sanitized_value(self):
        """FirehoseClient - Sanitized Value"""
        expected_result = 'test_log_type_name'
        result = FirehoseClient.sanitized_value('test*log.type-name')
        assert result == expected_result

    def test_enabled_log_source(self):
        """FirehoseClient - Enabled Log Source"""
        log = 'enabled_log'
        FirehoseClient._ENABLED_LOGS = {
            log: 'enabled:log'
        }
        assert FirehoseClient.enabled_log_source(log)

    def test_enabled_log_source_false(self):
        """FirehoseClient - Enabled Log Source, False"""
        log = 'enabled_log'
        assert FirehoseClient.enabled_log_source(log) == False

    def test_load_enabled_sources(self):
        """FirehoseClient - Load Enabled Log Sources"""
        logs_config = {
            'log_type_01:sub_type_01': {},
            'log_type_01:sub_type_02': {},  # This log type should is not enabled
            'log_type_02:sub_type_01': {},
            'log_type_02:sub_type_02': {},
        }
        firehose_config = {
            'enabled_logs': [
                'log_type_01:sub_type_01',  # One log for log_type_01
                'log_type_02'  # All of log_type_02
            ]
        }
        expected_result = {
            'log_type_01_sub_type_01': 'log_type_01:sub_type_01',
            'log_type_02_sub_type_01': 'log_type_02:sub_type_01',
            'log_type_02_sub_type_02': 'log_type_02:sub_type_02'
        }

        enabled_logs = FirehoseClient.load_enabled_log_sources(firehose_config, logs_config)
        assert enabled_logs == expected_result

    @patch('logging.Logger.error')
    def test_load_enabled_sources_invalid_log(self, log_mock):
        """FirehoseClient - Load Enabled Log Sources, Invalid Log Type"""
        logs_config = {
            'log_type_01:sub_type_01': {},
            'log_type_01:sub_type_02': {}
        }
        log_type = 'log_type_03'
        firehose_config = {
            'enabled_logs': [
                log_type
            ]
        }

        enabled_logs = FirehoseClient.load_enabled_log_sources(firehose_config, logs_config)
        assert enabled_logs == {}
        log_mock.assert_called_with(
            'Enabled Firehose log %s not declared in logs.json', log_type
        )

    @patch('logging.Logger.error')
    def test_load_enabled_sources_invalid_log_subtype(self, log_mock):
        """FirehoseClient - Load Enabled Log Sources, Invalid Log Sub-type"""
        logs_config = {
            'log_type_01:sub_type_01': {}
        }
        log_type = 'log_type_01:sub_type_02'
        firehose_config = {
            'enabled_logs': [
                log_type
            ]
        }

        enabled_logs = FirehoseClient.load_enabled_log_sources(firehose_config, logs_config)
        assert enabled_logs == {}
        log_mock.assert_called_with(
            'Enabled Firehose log %s not declared in logs.json', log_type
        )

    def test_load_from_config(self):
        """FirehoseClient - Load From Config"""
        with patch('boto3.client'):  # patch to speed up unit tests slightly
            client = FirehoseClient.load_from_config(
                prefix='unit-test',
                firehose_config={'enabled': True},
                log_sources=None
            )
            assert isinstance(client, FirehoseClient)

    def test_load_from_config_disabled(self):
        """FirehoseClient - Load From Config, Disabled"""
        client = FirehoseClient.load_from_config(
            prefix='unit-test',
            firehose_config={},
            log_sources=None
        )
        assert client is None

    @patch.object(FirehoseClient, '_send_batch')
    def test_send(self, send_batch_mock):
        """FirehoseClient - Send"""
        FirehoseClient._ENABLED_LOGS = {
            'log_type_01_sub_type_01': 'log_type_01:sub_type_01'
        }
        expected_batch = [
            '{"unit_key_01":1,"unit_key_02":"test"}\n',
            '{"unit_key_01":2,"unit_key_02":"test"}\n'
        ]
        self._client.send(self._sample_payloads)
        send_batch_mock.assert_called_with(
            'unit_test_streamalert_log_type_01_sub_type_01', expected_batch, 'classifier'
        )

    @patch.object(FirehoseClient, '_send_batch')
    def test_send_no_prefixing(self, send_batch_mock):
        """FirehoseClient - Send, No Prefixing"""
        FirehoseClient._ENABLED_LOGS = {
            'log_type_01_sub_type_01': 'log_type_01:sub_type_01'
        }
        expected_batch = [
            '{"unit_key_01":1,"unit_key_02":"test"}\n',
            '{"unit_key_01":2,"unit_key_02":"test"}\n'
        ]

        client = FirehoseClient.load_from_config(
            prefix='unit-test',
            firehose_config={'enabled': True, 'use_prefix': False},
            log_sources=None
        )

        client.send(self._sample_payloads)
        send_batch_mock.assert_called_with(
            'streamalert_log_type_01_sub_type_01', expected_batch, 'classifier'
        )

    @property
    def _sample_payloads_long_log_name(self):
        return [
            Mock(
                log_schema_type=(
                    'very_very_very_long_log_stream_name_abcdefg_hijklmn_70_characters_long'
                ),
                parsed_records=[
                    {
                        'unit_key_01': 1,
                        'unit_key_02': 'test'
                    },
                    {
                        'unit_key_01': 2,
                        'unit_key_02': 'test'
                    }
                ]
            )
        ]

    @patch.object(FirehoseClient, '_send_batch')
    def test_send_long_log_name(self, send_batch_mock):
        """FirehoseClient - Send data when the log name is very long"""
        FirehoseClient._ENABLED_LOGS = {
            'very_very_very_long_log_stream_name_abcdefg_hijklmn_70_characters_long': {}
        }
        expected_batch = [
            '{"unit_key_01":1,"unit_key_02":"test"}\n',
            '{"unit_key_01":2,"unit_key_02":"test"}\n'
        ]

        client = FirehoseClient.load_from_config(
            prefix='unit-test',
            firehose_config={'enabled': True, 'use_prefix': False},
            log_sources=None
        )

        client.send(self._sample_payloads_long_log_name)
        send_batch_mock.assert_called_with(
            'streamalert_very_very_very_long_log_stream_name_abcdefg_7c88167b',
            expected_batch,
            'classifier'
        )

    def test_generate_firehose_name(self):
        """FirehoseClient - Test helper to generate firehose stream name when prefix disabled"""
        log_names = [
            'logstreamname',
            'log_stream_name',
            'very_very_long_log_stream_name_ab_52_characters_long',
            'very_very_very_long_log_stream_name_abcdefg_abcdefg_70_characters_long'
        ]

        expected_results = [
            'streamalert_logstreamname',
            'streamalert_log_stream_name',
            'streamalert_very_very_long_log_stream_name_ab_52_characters_long',
            'streamalert_very_very_very_long_log_stream_name_abcdefg_272fa762'
        ]
        results = [
            self._client.generate_firehose_name('', log_name)
            for log_name in log_names
        ]

        assert expected_results == results

    def test_generate_firehose_name_prefix(self):
        """FirehoseClient - Test helper to generate firehose stream name with prefix"""
        log_names = [
            'logstreamname',
            'log_stream_name',
            'very_very_long_log_stream_name_ab_52_characters_long',
            'very_very_very_long_log_stream_name_abcdefg_abcdefg_70_characters_long'
        ]

        expected_results = [
            'prefix_streamalert_logstreamname',
            'prefix_streamalert_log_stream_name',
            'prefix_streamalert_very_very_long_log_stream_name_ab_52_63bd84dc',
            'prefix_streamalert_very_very_very_long_log_stream_name_a0c91e099'
        ]
        results = [
            self._client.generate_firehose_name('prefix', log_name)
            for log_name in log_names
        ]

        assert expected_results == results

    def test_artifacts_firehose_stream_name(self):
        """FirehoseClient - Test generate artifacts firehose stream name"""
        config_data = {
            'global': {
                'account': {
                    'prefix': 'unittest'
                }
            },
            'lambda': {
                'artifact_extractor_config': {}
            }
        }

        assert (
            self._client.artifacts_firehose_stream_name(config_data) ==
            'unittest_streamalert_artifacts')

        config_data['lambda']['artifact_extractor_config']['firehose_stream_name'] = (
            'test_artifacts_fh_name'
        )

        assert (
            self._client.artifacts_firehose_stream_name(config_data) ==
            'test_artifacts_fh_name')

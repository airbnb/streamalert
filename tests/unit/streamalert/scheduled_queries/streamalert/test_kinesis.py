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
from unittest.mock import MagicMock

from moto import mock_kinesis

from streamalert.scheduled_queries.streamalert.kinesis import KinesisClient


@mock_kinesis
class TestKinesisClient:
    def __init__(self):
        self._logger = None
        self._kinesis = None
        self._client = None

    # Moto can't mock boto3.Session because boto3 is garbage and is utterly useless
    def setup(self):
        self._client = MagicMock(name='KinesisClient')

        self._logger = MagicMock()
        self._kinesis = KinesisClient(
            client=self._client,
            kinesis_stream='zabsbsbf',
            logger=self._logger
        )

    def test_success(self):
        """StreamQuery - KinesisClient - send_query_results - positive case"""
        query_pack = MagicMock()
        query_pack.query_result.headers = ['header1', 'header2']
        query_pack.query_result.data_as_dicts = [{'header1': 'a', 'header2': 'b'}]
        query_pack.query_result.count = 1

        query_pack.query_execution.query_execution_id = '1111-aaaa-bbbb-2222'

        query_pack.query_pack_configuration.name = 'test_name'
        query_pack.query_pack_configuration.description = 'description?'
        query_pack.query_execution.query = 'SELECT * FROM yayifications;'
        query_pack.query_parameters = {'dt': '2020'}
        query_pack.query_execution.data_scanned_in_bytes = 123
        query_pack.query_execution.engine_execution_time_in_millis = 345
        query_pack.query_pack_configuration.tags = ['daily']

        self._client.put_records.return_value = {
            'ResponseMetadata': {
                'HTTPStatusCode': 200
            }
        }

        self._kinesis.send_query_results(query_pack)

        self._logger.info.assert_any_call('  Success.')
        self._logger.info.assert_any_call('Done.')

    def test_failure(self):
        """StreamQuery - KinesisClient - send_query_results - negative case"""
        query_pack = MagicMock()
        query_pack.query_result.headers = ['header1', 'header2']
        query_pack.query_result.data_as_dicts = [{'header1': 'a', 'header2': 'b'}]
        query_pack.query_result.count = 1

        query_pack.query_execution.query_execution_id = '1111-aaaa-bbbb-2222'

        query_pack.query_pack_configuration.name = 'test_name'
        query_pack.query_pack_configuration.description = 'description?'
        query_pack.query_execution.query = 'SELECT * FROM yayifications;'
        query_pack.query_parameters = {'dt': '2020'}
        query_pack.query_execution.data_scanned_in_bytes = 123
        query_pack.query_execution.engine_execution_time_in_millis = 345
        query_pack.query_pack_configuration.tags = ['daily']

        self._client.put_records.return_value = {
            'ResponseMetadata': {
                'HTTPStatusCode': 400
            }
        }

        self._kinesis.send_query_results(query_pack)

        self._logger.info.assert_any_call('  ERROR!')
        self._logger.info.assert_any_call('Done.')

    def test_error_results(self):
        """StreamQuery - KinesisClient - send_error_results - positive case"""
        query_pack = MagicMock()
        query_pack.query_result.headers = ['header1', 'header2']
        query_pack.query_result.data_as_dicts = [{'header1': 'a', 'header2': 'b'}]
        query_pack.query_result.count = 1

        query_pack.query_execution.query_execution_id = '1111-aaaa-bbbb-2222'

        query_pack.query_pack_configuration.name = 'test_name'
        query_pack.query_pack_configuration.description = 'description?'
        query_pack.query_execution.query = 'SELECT * FROM yayifications;'
        query_pack.query_parameters = {'dt': '2020'}
        query_pack.query_execution.data_scanned_in_bytes = 123
        query_pack.query_execution.engine_execution_time_in_millis = 345
        query_pack.query_pack_configuration.tags = ['daily']

        query_pack.query_execution.status_description = 'ERROR'

        self._client.put_records.return_value = {
            'ResponseMetadata': {
                'HTTPStatusCode': 200
            }
        }

        self._kinesis.send_error_results(query_pack)

        self._logger.info.assert_any_call('  Success.')
        self._logger.info.assert_any_call('Done.')

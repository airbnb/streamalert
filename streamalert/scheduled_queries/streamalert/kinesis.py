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
import json


class KinesisClient:
    """Encapsulation of all communication with and data structures sent to StreamAlert Kinesis"""

    STREAMQUERY_SCHEMA_VERSION = '1.0.0'

    def __init__(self, logger, client=None, kinesis_stream=None):
        self._logger = logger
        self._kinesis_stream = kinesis_stream
        self._client = client

    def send_query_results(self, query_pack):
        """Generates a request to Kinesis given the streamquery results, and dispatches them.

        Args:
            query_pack (QueryPack): The QueryPack that successfully completed.
        """
        result = query_pack.query_result  # type: AthenaQueryResult
        query = query_pack.query_pack_configuration  # type: QueryPackConfiguration

        query_execution_id = query_pack.query_execution.query_execution_id
        console_link = f'https://us-east-1.console.aws.amazon.com/athena/home?region=us-east-1#query/history/{query_execution_id}'

        streamquery_result = {
            "streamquery_schema_version": self.STREAMQUERY_SCHEMA_VERSION,
            "execution": {
                "name": query.name,
                "description": query.description,
                "query": query_pack.query_execution.query,
                "query_parameters": query_pack.query_parameters,
                "data_scanned_in_bytes": query_pack.query_execution.data_scanned_in_bytes,
                "execution_time_ms": query_pack.query_execution.engine_execution_time_in_millis,
                "tags": query.tags,
                "query_execution_id": query_execution_id,
                "console_link": console_link,
            },
            "data": {
                "headers": result.headers,
                "rows": result.data_as_dicts,
                "count": result.count,
            },
        }

        self._logger.info(f'Sending StreamQuery record to kinesis stream: {self._kinesis_stream}')

        self._logger.debug(json.dumps(streamquery_result, indent=2, separators=(', ', ': ')))

        response = self._client.put_records(Records=[
            {
                'Data': json.dumps(streamquery_result),
                'PartitionKey': 'partitionKeyFoo'
            },
        ],
                                            StreamName=self._kinesis_stream)
        self._logger.debug(response)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            self._logger.info('  Success.')
        else:
            self._logger.info('  ERROR!')

        self._logger.info('Done.')

    def send_error_results(self, query_pack):
        """Send Kinesis record to StreamAlert upon query failure

        In this case, there is no result.

        Args:
            query_pack (QueryPack): The QueryPack that failed to complete.
        """
        query = query_pack.query_pack_configuration  # type: QueryPackConfiguration

        query_execution_id = query_pack.query_execution.query_execution_id
        console_link = f'https://us-east-1.console.aws.amazon.com/athena/home?region=us-east-1#query/history/{query_execution_id}'

        streamquery_result = {
            "streamquery_schema_version": self.STREAMQUERY_SCHEMA_VERSION,
            "execution": {
                "name": query.name,
                "description": query.description,
                "query": query_pack.query_execution.query,
                "query_parameters": query_pack.query_parameters,
                "data_scanned_in_bytes": query_pack.query_execution.data_scanned_in_bytes,
                "execution_time_ms": query_pack.query_execution.engine_execution_time_in_millis,
                "tags": query.tags,
                "query_execution_id": query_execution_id,
                "console_link": console_link,
                "error": {
                    "description": query_pack.query_execution.status_description
                },
            },
            "data": {
                "headers": [],
                "rows": [],
                "count": 0,
            },
        }

        self._logger.info(f'Sending StreamQuery record to kinesis stream: {self._kinesis_stream}')

        self._logger.debug(json.dumps(streamquery_result, indent=2, separators=(', ', ': ')))

        response = self._client.put_records(Records=[
            {
                'Data': json.dumps(streamquery_result),
                'PartitionKey': 'partitionKeyFoo'
            },
        ],
                                            StreamName=self._kinesis_stream)
        self._logger.debug(response)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            self._logger.info('  Success.')
        else:
            self._logger.info('  ERROR!')

        self._logger.info('Done.')

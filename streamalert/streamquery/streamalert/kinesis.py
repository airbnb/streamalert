import json

from streamalert.streamquery import __version__ as streamquery_version


class KinesisClient:
    """Encapsulation of all communication with and data structures sent to StreamAlert Kinesis"""

    def __init__(self, logger, client=None, kinesis_stream=None):
        self._logger = logger
        self._kinesis_stream = kinesis_stream
        self._client = client

    def send_query_results(self, query_pack):
        """Generates a request to Kinesis given the streamquery results, and dispatches them.

        Args:
            query_pack (QueryPack):

        Return:
            void
        """
        result = query_pack.query_result  # type: AthenaQueryResult
        query = query_pack.query_pack_configuration  # type: QueryPackConfiguration

        query_execution_id = query_pack.query_execution.query_execution_id
        console_link = (
            'https://us-east-1.console.aws.amazon.com/athena/home'
            '?region=us-east-1#query/history/{}'
        ).format(query_execution_id)
        streamquery_result = {
            "streamquery_schema_version": streamquery_version,
            "execution": {
                "handler": query.handler,
                "name": query.name,
                "description": query.description,
                "query": query_pack.query_execution.query,
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

        self._logger.info(
            'Sending StreamQuery record to kinesis stream: {}'.format(self._kinesis_stream)
        )
        self._logger.debug(json.dumps(streamquery_result, indent=2, separators=(', ', ': ')))

        response = self._client.put_records(
            Records=[
                {
                    'Data': json.dumps(streamquery_result),
                    'PartitionKey': 'partitionKeyFoo'
                },
            ],
            StreamName=self._kinesis_stream
        )
        self._logger.debug(response)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            self._logger.info('  Success.')
        else:
            self._logger.info('  ERROR!')

        self._logger.info('Done.')

    def send_error_results(self, query_pack):
        """Send Kinesis record to StreamAlert upon query failure

        In this case, there is no result.
        """
        query = query_pack.query_pack_configuration  # type: QueryPackConfiguration

        query_execution_id = query_pack.query_execution.query_execution_id
        console_link = (
            'https://us-east-1.console.aws.amazon.com/athena/home'
            '?region=us-east-1#query/history/{}'
        ).format(query_execution_id)
        streamquery_result = {
            "streamquery_schema_version": streamquery_version,
            "execution": {
                "handler": query.handler,
                "name": query.name,
                "description": query.description,
                "query": query_pack.query_execution.query,
                "data_scanned_in_bytes": query_pack.query_execution.data_scanned_in_bytes,
                "execution_time_ms": query_pack.query_execution.engine_execution_time_in_millis,
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

        self._logger.info(
            'Sending StreamQuery record to kinesis stream: {}'.format(self._kinesis_stream)
        )
        self._logger.debug(json.dumps(streamquery_result, indent=2, separators=(', ', ': ')))

        response = self._client.put_records(
            Records=[
                {
                    'Data': json.dumps(streamquery_result),
                    'PartitionKey': 'partitionKeyFoo'
                },
            ],
            StreamName=self._kinesis_stream
        )
        self._logger.debug(response)

        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            self._logger.info('  Success.')
        else:
            self._logger.info('  ERROR!')

        self._logger.info('Done.')

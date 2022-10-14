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
from datetime import datetime
from unittest.mock import MagicMock

from dateutil.tz import tzlocal

from streamalert.scheduled_queries.handlers.athena import (
    AthenaClient, AthenaQueryExecution, AthenaQueryResult)


class TestAthenaClient:
    def __init__(self):
        self._athena = None  # type: AthenaClient
        self._athena_client = None

    def setup(self):
        self._athena_client = MagicMock(name='AwsAthenaClient')

        self._athena = AthenaClient(
            logger=MagicMock(name='Logger'),
            client=self._athena_client
        )

    def test_run_async_query(self):
        """StreamQuery - AthenaClient - run_async_query"""
        self._athena_client.start_query_execution.return_value = {
            'QueryExecutionId': 'aaaa-bbbb-cccc-dddd'
        }
        result = self._athena.run_async_query('SELECT * FROM garbage_can')

        assert result == 'aaaa-bbbb-cccc-dddd'

        # We could assert the QueryString is correct.... but  It's annoying to get the
        # uuid of the ResultConfiguration... so leave that to future derek to figure out
        self._athena_client.start_query_execution.assert_called_once()

    def test_get_query_execution(self):
        """StreamQuery - AthenaClient - get_query_execution"""

        self._athena_client.get_query_execution.return_value = (
            TestAthenaQueryExecution.SAMPLE_RUNNING_RESPONSE
        )
        query_execution = self._athena.get_query_execution('e5b4a7e1-270b-42f8-8062-cfc5daa1e97f')

        self._athena_client.get_query_execution.assert_called_with(
            QueryExecutionId='e5b4a7e1-270b-42f8-8062-cfc5daa1e97f'
        )

        assert query_execution.query_execution_id == 'e5b4a7e1-270b-42f8-8062-cfc5daa1e97f'

    def test_get_query_result(self):
        """StreamQuery - AthenaClient - get_query_result"""

        self._athena_client.get_query_execution.return_value = (
            TestAthenaQueryExecution.SAMPLE_RUNNING_RESPONSE
        )
        query_execution = self._athena.get_query_execution('e5b4a7e1-270b-42f8-8062-cfc5daa1e97f')

        self._athena_client.get_query_execution.assert_called_with(
            QueryExecutionId='e5b4a7e1-270b-42f8-8062-cfc5daa1e97f'
        )

        assert query_execution.query_execution_id == 'e5b4a7e1-270b-42f8-8062-cfc5daa1e97f'


class TestAthenaQueryExecution:
    SAMPLE_RUNNING_RESPONSE = {
        'QueryExecution': {
            'QueryExecutionId': 'e5b4a7e1-270b-42f8-8062-cfc5daa1e97f',
            'Query': 'SELECT * FROM garbage_can',
            'StatementType': 'DML',
            'ResultConfiguration': {
                'OutputLocation': 's3://aws-athena-query-results.csv'
            },
            'QueryExecutionContext': {
                'Database': 'streamalert'
            },
            'Status': {
                'State': 'RUNNING',
                'SubmissionDateTime': datetime(2019, 6, 5, 21, 50, 15, 525000, tzinfo=tzlocal())
            },
            'Statistics': {
                'EngineExecutionTimeInMillis': 4414,
                'DataScannedInBytes': 0
            },
            'WorkGroup': 'primary'
        },
        'ResponseMetadata': {
            'RequestId': '4bcb8b9b-7f32-431d-8545-20a04621078f',
            'HTTPStatusCode': 200,
            'HTTPHeaders': {
                'content-type': 'application/x-amz-json-1.1',
                'date': 'Thu, 06 Jun 2019 04:50:21 GMT',
                'x-amzn-requestid': '4bcb8b9b-7f32-431d-8545-20a04621078f',
                'content-length': '2179',
                'connection': 'keep-alive'
            },
            'RetryAttempts': 0
        }
    }
    SAMPLE_SUCCEEDED_RESPONSE = {
        'QueryExecution': {
            'QueryExecutionId': '79b025ac-80b5-4cc5-b7d3-7f84fb1b0562',
            'Query': "SELECT * FROM garbage_can",
            'StatementType': 'DML', 'ResultConfiguration': {
                'OutputLocation': 's3://aws-athena-query-results-569589067625.csv'
            },
            'QueryExecutionContext': {
                'Database': 'streamalert'
            },
            'Status': {
                'State': 'SUCCEEDED',
                'SubmissionDateTime': (
                    datetime(2019, 6, 5, 21, 50, 15, 366000, tzinfo=tzlocal())
                ),
                'CompletionDateTime': datetime(2019, 6, 5, 21, 50, 21, 770000, tzinfo=tzlocal())
            },
            'Statistics': {
                'EngineExecutionTimeInMillis': 6166,
                'DataScannedInBytes': 26358801
            },
            'WorkGroup': 'primary'
        },
        'ResponseMetadata': {
            'RequestId': 'b673e49a-da1d-4050-930b-af33941c892a',
            'HTTPStatusCode': 200,
            'HTTPHeaders': {
                'content-type': 'application/x-amz-json-1.1',
                'date': 'Thu, 06 Jun 2019 04:50:21 GMT',
                'x-amzn-requestid': 'b673e49a-da1d-4050-930b-af33941c892a',
                'content-length': '1945',
                'connection': 'keep-alive'
            },
            'RetryAttempts': 0
        }
    }

    def __init__(self):
        self._running_execution = None  # type: AthenaQueryExecution
        self._succeeded_execution = None  # type: AthenaQueryExecution

    def setup(self):
        # This is a redacted response I pulled from an actual request
        self._running_execution = AthenaQueryExecution(self.SAMPLE_RUNNING_RESPONSE)

        # This is a redacted response I pulled from an actual request
        self._succeeded_execution = AthenaQueryExecution(self.SAMPLE_SUCCEEDED_RESPONSE)

    def test_query_execution_id(self):
        """StreamQuery - AthenaQueryExecution - query_execution_id"""
        assert (
            self._running_execution.query_execution_id ==
            'e5b4a7e1-270b-42f8-8062-cfc5daa1e97f')

    def test_database(self):
        """StreamQuery - AthenaQueryExecution - database"""
        assert self._running_execution.database == 'streamalert'

    def test_status(self):
        """StreamQuery - AthenaQueryExecution - status"""
        assert self._running_execution.status == 'RUNNING'
        assert self._succeeded_execution.status == 'SUCCEEDED'

    def test_status_description(self):
        """StreamQuery - AthenaQueryExecution - status_description"""
        assert self._running_execution.status_description is None

    def test_completion_datetime(self):
        """StreamQuery - AthenaQueryExecution - completion_datetime"""
        assert (
            self._succeeded_execution.completion_datetime ==
            datetime(2019, 6, 5, 21, 50, 21, 770000, tzinfo=tzlocal()))

    def test_data_scanned_in_bytes(self):
        """StreamQuery - AthenaQueryExecution - data_scanned_in_bytes"""
        assert self._succeeded_execution.data_scanned_in_bytes == 26358801

    def test_engine_execution_time_in_millis(self):
        """StreamQuery - AthenaQueryExecution - engine_execution_time_in_millis"""
        assert self._succeeded_execution.engine_execution_time_in_millis == 6166

    def test_output_location(self):
        """StreamQuery - AthenaQueryExecution - output_location"""
        assert (
            self._succeeded_execution.output_location ==
            's3://aws-athena-query-results-569589067625.csv')

    def test_query(self):
        """StreamQuery - AthenaQueryExecution - query"""
        assert self._succeeded_execution.query == 'SELECT * FROM garbage_can'

    def test_is_still_running(self):
        """StreamQuery - AthenaQueryExecution - is_still_running"""
        assert self._running_execution.is_still_running()
        assert not self._succeeded_execution.is_still_running()

    def test_is_succeeded(self):
        """StreamQuery - AthenaQueryExecution - is_succeeded"""
        assert not self._running_execution.is_succeeded()
        assert self._succeeded_execution.is_succeeded()


class TestAthenaQueryResult:
    SAMPLE_RESULT = {
        'UpdateCount': 0,
        'ResultSet': {
            'Rows': [
                {
                    'Data': [
                        {'VarCharValue': 'date'},
                        {'VarCharValue': 'assume_role'},
                        {'VarCharValue': 'count'}
                    ]
                },
                {
                    'Data': [
                        {'VarCharValue': '2019-06-04'},
                        {},
                        {'VarCharValue': '1'}
                    ]
                },
                {
                    'Data': [
                        {'VarCharValue': '2019-06-04'},
                        {'VarCharValue': '"arn:aws:iam::172631448019:role/TF_ReadOnly"'},
                        {'VarCharValue': '1'}
                    ]
                }
            ],
            'ResultSetMetadata': {
                'ColumnInfo': [
                    {
                        'CatalogName': 'hive',
                        'SchemaName': '',
                        'TableName': '', 'Name': 'date',
                        'Label': 'date', 'Type': 'date',
                        'Precision': 0, 'Scale': 0,
                        'Nullable': 'UNKNOWN',
                        'CaseSensitive': False
                    },
                    {
                        'CatalogName': 'hive',
                        'SchemaName': '',
                        'TableName': '',
                        'Name': 'assume_role',
                        'Label': 'assume_role',
                        'Type': 'json',
                        'Precision': 0, 'Scale': 0,
                        'Nullable': 'UNKNOWN',
                        'CaseSensitive': False
                    },
                    {
                        'CatalogName': 'hive',
                        'SchemaName': '',
                        'TableName': '', 'Name': 'count',
                        'Label': 'count', 'Type': 'bigint',
                        'Precision': 19, 'Scale': 0,
                        'Nullable': 'UNKNOWN',
                        'CaseSensitive': False
                    }
                ]
            }
        },
        'ResponseMetadata': {
            'RequestId': '47306c01-387c-4699-acaf-eeb10e533fb9',
            'HTTPStatusCode': 200, 'HTTPHeaders': {
                'content-type': 'application/x-amz-json-1.1',
                'date': 'Thu, 06 Jun 2019 05:11:14 GMT',
                'x-amzn-requestid': '47306c01-387c-4699-acaf-eeb10e533fb9',
                'content-length': '1564', 'connection': 'keep-alive'
            },
            'RetryAttempts': 0
        }
    }

    def __init__(self):
        self._result = None  # type: AthenaQueryResult

    def setup(self):
        self._result = AthenaQueryResult(
            AthenaQueryExecution(TestAthenaQueryExecution.SAMPLE_SUCCEEDED_RESPONSE),
            self.SAMPLE_RESULT
        )

    def test_query_execution(self):
        """StreamQuery - AthenaQueryResult - query_execution"""
        assert isinstance(self._result.query_execution, AthenaQueryExecution)

    def test_headers(self):
        """StreamQuery - AthenaQueryResult - headers"""
        assert self._result.headers == ['date', 'assume_role', 'count']

    def test_data_as_list(self):
        """StreamQuery - AthenaQueryResult - data_as_list"""
        assert (
            self._result.data_as_list ==
            [
                ['2019-06-04', None, '1'],
                ['2019-06-04', '"arn:aws:iam::172631448019:role/TF_ReadOnly"', '1']
            ])

    def test_data_as_dicts(self):
        """StreamQuery - AthenaQueryResult - data_as_dicts"""
        assert (
            self._result.data_as_dicts ==
            [
                {'date': '2019-06-04', 'assume_role': None, 'count': '1'},
                {
                    'date': '2019-06-04',
                    'assume_role': '"arn:aws:iam::172631448019:role/TF_ReadOnly"',
                    'count': '1'
                },
            ])

    def test_data_as_human_string(self):
        """StreamQuery - AthenaQueryResult - human_string"""
        assert (
            self._result.data_as_human_string ==
            """
[
  {
    "date": "2019-06-04",
    "assume_role": null,
    "count": "1"
  },
  {
    "date": "2019-06-04",
    "assume_role": "\\"arn:aws:iam::172631448019:role/TF_ReadOnly\\"",
    "count": "1"
  }
]
""".strip())

    def test_count(self):
        """StreamQuery - AthenaQueryResult - count"""
        assert self._result.count == 2

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
import uuid

from botocore.exceptions import ClientError


class AthenaQueryExecutionError(Exception):
    """Exception to be raised when an Athena query fails"""


# FIXME (ryxias)
#   At some point we should DRY out the implementation of this API client with the one in
#   streamalert/shared/athena.py
class AthenaClient:
    """A StreamAlert Athena Client for creating tables, databases, and executing queries"""
    def __init__(self, logger=None, client=None, database=None, results_bucket=None):
        """Initialize the Boto3 Athena Client, and S3 results bucket/key"""
        self._logger = logger
        self._client = client
        self._database = database
        self._s3_results_bucket = results_bucket

    def _execute_query(self, query, options):
        """Execute an Athena query on the current database. This operation is non-blocking

        See:
            https://docs.aws.amazon.com/cli/latest/reference/athena/start-query-execution.html

        Args:
            query (str): SQL query to execute
            options (dict): Configuration options

                - database (str): The Athena database to connect to.

        Returns:
            str: Athena execution ID for the query that was started

        Raises:
            AthenaQueryExecutionError: If any failure occurs during the execution of the
                query, this exception will be raised
        """
        self._logger.debug('Executing query: %s', query)
        try:
            output_location = 's3://{bucket}/{key}.csv'.format(bucket=self._s3_results_bucket,
                                                               key=uuid.uuid4())
            result = self._client.start_query_execution(
                QueryString=query,
                QueryExecutionContext={'Database': options.get('database', self._database)},
                ResultConfiguration={'OutputLocation': output_location})
            query_execution_id = result['QueryExecutionId']
            self._logger.debug('Query dispatched. ID returned: %s', query_execution_id)

            return query_execution_id
        except ClientError as err:
            raise AthenaQueryExecutionError(f'Athena query failed:\n{err}') from err

    def get_query_execution(self, query_execution_id):
        """Gets an AthenaQueryExecution object encapsulating the result of a query

        Check the result.is_still_running() and result.is_succeeded() for the statuses
        of the queries.

        Args:
            query_execution_id (str): The Athena-returned query execution id

        Returns:
            AthenaQueryExecution
        """
        return AthenaQueryExecution(
            self._client.get_query_execution(QueryExecutionId=query_execution_id))

    def get_query_result(self, query_execution):
        """Returns a query result payload, wrapped in a AthenaQueryResult object

        Args:
            query_execution (AthenaQueryExecution)

        Returns:
            AthenaQueryResult
            Returns None if the given query_execution is not completed
        """
        return AthenaQueryResult(
            query_execution,
            self._client.get_query_results(QueryExecutionId=query_execution.query_execution_id)
        ) if query_execution.is_succeeded() else None

    def run_async_query(self, query, options=None):
        """Run an Athena query in an asynchronous fashion. This operation is non-blocking

        Args:
            query (str): SQL query to execute
            options (dict): Configuration options

        Returns:
            str: Athena query execution ID

        Raises:
            AthenaQueryExecutionError: If any failure occurs during the execution of the
                query, this exception will be raised
        """
        if options is None:
            options = {}

        return self._execute_query(query, options)


class AthenaQueryExecution:
    """Encapsulation of a query execution response

    See:
        https://docs.aws.amazon.com/cli/latest/reference/athena/get-query-execution.html
    """
    def __init__(self, response):
        self._response = response

    @property
    def query_execution_id(self):
        return self._response['QueryExecution']['QueryExecutionId']

    @property
    def database(self):
        return self._response['QueryExecution']['QueryExecutionContext']['Database']

    @property
    def status(self):
        return self._response['QueryExecution']['Status']['State']

    @property
    def status_description(self):
        return self._response['QueryExecution']['Status'].get('StateChangeReason', None)

    @property
    def completion_datetime(self):
        return self._response['QueryExecution']['Status']['CompletionDateTime']

    @property
    def data_scanned_in_bytes(self):
        return self._response['QueryExecution']['Statistics']['DataScannedInBytes']

    @property
    def engine_execution_time_in_millis(self):
        return self._response['QueryExecution']['Statistics']['EngineExecutionTimeInMillis']

    @property
    def output_location(self):
        return self._response['QueryExecution']['ResultConfiguration']['OutputLocation']

    @property
    def query(self):
        return self._response['QueryExecution']['Query']

    def is_still_running(self):
        return self.status in {'QUEUED', 'RUNNING'}

    def is_succeeded(self):
        return self.status == 'SUCCEEDED'


class AthenaQueryResult:
    """Encapsulation of a query execution's result"""
    def __init__(self, query_execution, result):
        self._query_execution = query_execution
        self._result = result

    @property
    def query_execution(self):
        """
        Returns:
            AthenaQueryExecution
        """
        return self._query_execution

    @property
    def headers(self):
        """Returns the headers of the query result, as a list

        Returns:
            list
        """
        return self._raw_row_to_list(self.raw_rows[0])

    @property
    def data_as_list(self):
        """Returns the data of the query result, as a list of lists

        The result set is a list of rows, in the order they appear in the query result.
        Each row is a list of column values, in the order they appear from left-to-right. This
        should match the ordering in the "headers".

        Returns:
            list[list]
        """
        return [self._raw_row_to_list(row) for row in self.raw_rows[1:]]

    @property
    def data_as_dicts(self):
        """Returns the data of the query results as a list of dicts mapping headers to values

        An alternative to data_as_list. The returned result is a list of rows, but in this method
        the rows are dicts, mapping the headers (keys) to their respective values.

        This method results in a larger data set and is more CPU intensive but the returned data
        is easier to use.

        Returns:
            list[dict]
        """
        headers = self.headers

        data = []
        for row in self.data_as_list:
            dict_row = {header: row[index] for index, header in enumerate(headers)}
            data.append(dict_row)
        return data

    @property
    def data_as_human_string(self):
        return json.dumps(self.data_as_dicts, indent=2, separators=(',', ': '))

    @property
    def raw_rows(self):
        return self._result['ResultSet']['Rows']

    @property
    def count(self):
        """Returns the number of rows in the result set"""
        return len(self.raw_rows) - 1  # Remove 1 to account for the header, which is always around

    @staticmethod
    def _raw_row_to_list(row):
        # For empty cells, there is no VarCharValue key
        return [cell.get('VarCharValue', None) for cell in row['Data']]

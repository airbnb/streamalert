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
import posixpath
from datetime import datetime

import backoff
import boto3
from botocore.exceptions import ClientError

import streamalert.shared.helpers.boto as boto_helpers
from streamalert.shared.backoff_handlers import (backoff_handler,
                                                 success_handler)
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


class AthenaQueryExecutionError(Exception):
    """Exception to be raised when an Athena query fails"""


class AthenaClient:
    """A StreamAlert Athena Client for creating tables, databases, and executing queries

    Attributes:
        database: Athena database name where tables will be queried
    """
    def __init__(self, database_name, results_bucket, results_prefix, region=None):
        """Initialize the Boto3 Athena Client, and S3 results bucket/key

        Args:
            database_name (str): Athena database name where tables will be queried
            results_bucket (str): S3 bucket in which to store Athena results
            results_prefix (str): S3 key prefix to prepend too results in the bucket
        """
        self._client = boto3.client('athena', config=boto_helpers.default_config(region=region))
        self.database = database_name.strip()

        results_bucket = results_bucket.strip()

        # Make sure the required 's3://' prefix is included
        if not results_bucket.startswith('s3://'):
            results_bucket = f's3://{results_bucket}'

        # Produces s3://<results_bucket_name>/<results_prefix>
        self._s3_results_path_prefix = posixpath.join(results_bucket, results_prefix)

    @property
    def results_path(self):
        # Returns a path for the current hour: /YYYY/MM/DD/HH
        return posixpath.join(self._s3_results_path_prefix,
                              datetime.utcnow().strftime('%Y/%m/%d/%H'))

    @staticmethod
    def _unique_values_from_query(query_result):
        """Reduce Athena query results into a set of values.

        Useful for listing tables, partitions, databases, enable_metrics

        Args:
            query_result (dict): Result of an athena query

        Returns:
            set: Unique values from the query result
        """
        return {
            value
            for row in query_result['ResultSet']['Rows'] for result in row['Data']
            for value in result.values()
        }

    def _execute_and_wait(self, query):
        """Execute an Athena query on the current database. This is a blocking operation

        Args:
            query (str): SQL query to execute

        Returns:
            str: Athena execution ID for the query that was executed

        Raises:
            AthenaQueryExecutionError: If any failure occurs during the execution of the
                query, this exception will be raised
        """
        response = self._execute_query(query)

        execution_id = response['QueryExecutionId']

        # This will block until the execution is complete, or raise an
        # AthenaQueryExecutionError exception if an error occurs
        self.check_query_status(execution_id)

        return execution_id

    def _execute_query(self, query):
        """Execute an Athena query on the current database. This operation is non-blocking

        Args:
            query (str): SQL query to execute

        Returns:
            dict: Response object with the status of the running query

        Raises:
            AthenaQueryExecutionError: If any failure occurs during the execution of the
                query, this exception will be raised
        """
        LOGGER.debug('Executing query: %s', query)
        try:
            return self._client.start_query_execution(
                QueryString=query,
                QueryExecutionContext={'Database': self.database},
                ResultConfiguration={'OutputLocation': self.results_path})
        except ClientError as err:
            raise AthenaQueryExecutionError(f'Athena query failed:\n{err}') from err

    def drop_all_tables(self):
        """Drop all table in the database

        Returns:
            bool: True if all tables were dropped successfully, False otherwise
        """
        result = self.run_query_for_results('SHOW TABLES')
        if not result:
            LOGGER.error('There was an issue getting all tables')
            return False

        unique_tables = self._unique_values_from_query(result)

        return all(self.drop_table(table) for table in unique_tables)

    def drop_table(self, table_name):
        """Drop a specific table in the database

        Args:
            table_name (str): Table name which should be dropped from the database

        Returns:
            bool: True if the table was successfully dropped, False otherwise
        """
        success = self.run_query(f'DROP TABLE {table_name}')
        if not success:
            LOGGER.error('Unable to drop table: %s', table_name)
            return False

        LOGGER.info('Successfully dropped table: %s', table_name)
        return True

    def get_table_partitions(self, table_name):
        """Get the list of partitions for a specific table in the database

        Args:
            table_name (str): Table name for which partitions should be returned

        Returns:
            set: Unique set of partitions for the given table
        """
        partitions = self.run_query_for_results(f'SHOW PARTITIONS {table_name}')
        if not partitions:
            LOGGER.error('An error occurred when loading partitions for %s', table_name)
            return

        return self._unique_values_from_query(partitions)

    def check_query_status(self, execution_id):
        """Check in on the running query, back off if the job is running or queued

        Args:
            query_execution_id (str): Athena query execution ID

        Returns:
            bool: True if the query state is SUCCEEDED, False otherwise
                Reference https://bit.ly/2uuRtda.

        Raises:
            AthenaQueryExecutionError: If any failure occurs while checking the status of the
                query, this exception will be raised
        """
        LOGGER.debug('Checking status of query with execution ID: %s', execution_id)

        states_to_backoff = {'QUEUED', 'RUNNING'}

        @backoff.on_predicate(
            backoff.fibo,
            lambda resp: resp['QueryExecution']['Status']['State'] in states_to_backoff,
            max_value=10,
            jitter=backoff.full_jitter,
            on_backoff=backoff_handler(),
            on_success=success_handler(True))
        def _check_status(query_execution_id):
            return self._client.get_query_execution(QueryExecutionId=query_execution_id)

        execution_result = _check_status(execution_id)
        state = execution_result['QueryExecution']['Status']['State']
        if state == 'SUCCEEDED':
            return

        # When the state is not SUCCEEDED, something bad must have occurred, so raise an exception
        reason = execution_result['QueryExecution']['Status']['StateChangeReason']
        raise AthenaQueryExecutionError('Query \'{}\' {} with reason \'{}\', exiting'.format(
            execution_id, state, reason))

    def query_result_paginator(self, query):
        """Iterate over all results returned by the Athena query. This is a blocking operation

        Args:
            query (str): SQL query to execute

        Yields:
            dict: Response objects with the results of the running query

        Raises:
            AthenaQueryExecutionError: If any failure occurs during the execution of the
                query, this exception will be raised
        """
        execution_id = self._execute_and_wait(query)

        paginator = self._client.get_paginator('get_query_results')

        yield from paginator.paginate(QueryExecutionId=execution_id)

    def run_async_query(self, query):
        """Run an Athena query in an asynchronous fashion. This operation is non-blocking

        Args:
            query (str): SQL query to execute

        Returns:
            dict: Response object with the status of the running query

        Raises:
            AthenaQueryExecutionError: If any failure occurs during the execution of the
                query, this exception will be raised
        """
        return self._execute_query(query)

    def run_query(self, query):
        """Run an Athena query and just check for success. This is a blocking operation

        Args:
            query (str): SQL query to execute

        Returns:
            bool: True if the query ran successfully, False otherwise

        Raises:
            AthenaQueryExecutionError: If any failure occurs during the execution of the
                query, this exception will be raised
        """
        return bool(self._execute_and_wait(query))

    def run_query_for_results(self, query):
        """Run Athena queries and get results back. This is a blocking operation

        Args:
            query (str): SQL query to execute

        Returns:
            dict: Response object with the result of the running query

        Raises:
            AthenaQueryExecutionError: If any failure occurs during the execution of the
                query, this exception will be raised
        """
        execution_id = self._execute_and_wait(query)
        query_results = self._client.get_query_results(QueryExecutionId=execution_id)

        # The idea here is to leave the processing logic to the calling functions.
        # No data being returned isn't always an indication that something is wrong.
        # When handling the query result data, iterate over each element in the Row,
        # and parse the Data key.
        # Reference: https://bit.ly/2tWOQ2N
        if not query_results['ResultSet']['Rows']:
            LOGGER.debug('The query %s returned empty rows of data', query)

        return query_results

    def check_database_exists(self):
        """Verify the Athena database being used exists. This is a blocking operation"""
        response = self.run_query_for_results(f"SHOW DATABASES LIKE \'{self.database}\';")

        return bool(response and response['ResultSet']['Rows'])

    def check_table_exists(self, table_name):
        """Verify a given Athena table exists within the database. This is a blocking operation

        Args:
            table_name (str): Table name whose existence is being verified
        """
        result = self.run_query_for_results(f"SHOW TABLES LIKE \'{table_name}\';")

        return bool(result and result['ResultSet']['Rows'])

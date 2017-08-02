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

import json
import logging
import os

from datetime import datetime

import backoff
import boto3

logging.basicConfig()
LEVEL = os.environ.get('LOGGER_LEVEL', 'INFO')
LOGGER = logging.getLogger('StreamAlertAthena')
LOGGER.setLevel(LEVEL.upper())


class ConfigError(Exception):
    """Custom StreamAlertAthena Config Exception Class"""
    pass


class StreamAlertAthenaClient(object):
    DATABASE_DEFAULT = 'default'
    DATABASE_STREAMALERT = 'streamalert'
    DEFAULT_S3_PREFIX = 'athena_partition_refresh'

    def __init__(self, **kwargs):
        """Initialize the Boto3 Athena Client, and S3 results bucket/key

        Keyword Arguments:
            config [CLIConfig]: Loaded StreamAlert configuration (optional)
            results_key_prefix [string]: The S3 key prefix to store Athena results (optional)
        """
        # Load the config from files or accept it as an argument
        self.config = kwargs.get('config') or self._load_config()
        region = self.config['global']['account']['region']
        self.athena_client = boto3.client('athena', region_name=region)

        # Format the S3 bucket to store Athena query results
        self.athena_results_bucket = 's3://aws-athena-query-results-{}-{}'.format(
            self.config['global']['account']['aws_account_id'],
            self.config['global']['account']['region'])

        # Format the S3 key to store specific objects
        results_key_prefix = kwargs.get('results_key_prefix', self.DEFAULT_S3_PREFIX)
        # Produces athena_partition_refresh/YYYY/MM/DD S3 keys
        self.athena_results_key = os.path.join(
            results_key_prefix,
            datetime.now().strftime('%Y/%m/%d'))

    @staticmethod
    def _load_config():
        """Load the StreamAlert Athena configuration files

        Returns:
            [dict] Configuration settings by file, includes two keys:
                lambda: All lambda function settings
                global: StreamAlert global settings

        Raises:
            [ConfigError] For invalid or missing configuration files.
        """
        config_files = ('lambda', 'global')
        config = {}
        for config_file in config_files:
            config_file_path = 'conf/{}.json'.format(config_file)

            if not os.path.exists(config_file_path):
                raise ConfigError('The \'{}\' config file was not found'.format(
                    config_file_path))

            with open(config_file_path) as config_fh:
                try:
                    config[config_file] = json.load(config_fh)
                except ValueError:
                    raise ConfigError('The \'{}\' config file is not valid JSON'.format(
                        config_file))

        return config

    @staticmethod
    def _backoff_handler(details):
        """Simple logging handler for when polling backoff occurs."""
        LOGGER.debug('[Backoff]: Trying again in %f seconds after %d tries calling %s',
                     details['wait'],
                     details['tries'],
                     details['target'])

    @staticmethod
    def _success_handler(details):
        """Simple logging handler for when polling backoff occurs."""
        LOGGER.debug('[Backoff]: Completed after %d tries calling %s',
                     details['tries'],
                     details['target'])

    def check_query_status(self, query_execution_id):
        """Check in on the running query, back off if the job is running or queued

        Returns:
            [string]: The result of the query, this can be SUCCEEDED, FAILED, or CANCELLED.
                      Reference https://bit.ly/2uuRtda
        """
        @backoff.on_predicate(backoff.fibo,
                              lambda status: status in ('QUEUED', 'RUNNING'),
                              max_value=10,
                              jitter=backoff.full_jitter,
                              on_backoff=self._backoff_handler,
                              on_success=self._success_handler)
        def _get_query_execution(query_execution_id):
            return self.athena_client.get_query_execution(
                QueryExecutionId=query_execution_id
            )['QueryExecution']['Status']['State']

        return _get_query_execution(query_execution_id)

    def run_athena_query(self, **kwargs):
        """Helper function to run Athena queries

        Keyword Args:
            query [string]: The SQL query to execute
            database [string]: The database context to execute the query in

        Returns:
            tuple: [bool]: Query success, [dict]: Query result response
        """
        LOGGER.debug('Executing query: %s', kwargs['query'])
        query_execution_resp = self.athena_client.start_query_execution(
            QueryString=kwargs['query'],
            QueryExecutionContext={'Database': kwargs.get('database', self.DATABASE_DEFAULT)},
            ResultConfiguration={'OutputLocation': '{}/{}'.format(
                self.athena_results_bucket,
                self.athena_results_key
            )}
        )

        query_execution_result = self.check_query_status(
            query_execution_resp['QueryExecutionId'])

        if query_execution_result != 'SUCCEEDED':
            LOGGER.error(
                'The query %s returned %s, exiting!',
                kwargs['query'],
                query_execution_result)
            return False, {}

        query_results_resp = self.athena_client.get_query_results(
            QueryExecutionId=query_execution_resp['QueryExecutionId'],
        )

        # The idea here is to leave the processing logic to the calling functions.
        # No data being returned isn't always an indication that something is wrong.
        # When handling the query result data, iterate over each element in the Row,
        # and parse the Data key.
        # Reference: https://bit.ly/2tWOQ2N
        if not query_results_resp['ResultSet']['Rows']:
            LOGGER.debug('The query %s returned empty rows of data', kwargs['query'])

        return True, query_results_resp

    def check_database_exists(self, **kwargs):
        """Verify the StreamAlert Athena database exists."""
        database = kwargs.get('database', self.DATABASE_STREAMALERT)
        query_success, query_resp = self.run_athena_query(
            query='SHOW DATABASES LIKE \'{}\';'.format(database),
        )

        if query_success and query_resp['ResultSet']['Rows']:
            return True
        else:
            LOGGER.error('The \'%s\' database does not exist. '
                         'Create it with the following command: \n'
                         '$ python stream_alert_cli.py athena create-db',
                         database)
            return False

    def check_table_exists(self, table_name):
        """Verify a given StreamAlert Athena table exists."""
        query_success, query_resp = self.run_athena_query(
            query='SHOW TABLES LIKE \'{}\';'.format(table_name),
            database=self.DATABASE_STREAMALERT
        )

        if query_success and query_resp['ResultSet']['Rows']:
            return True
        else:
            LOGGER.info('The streamalert table \'%s\' does not exist. '
                        'For alert buckets, create it with the following command: \n'
                        '$ python stream_alert_cli.py athena create-table '
                        '--type alerts --bucket s3.bucket.id',
                        table_name)
            return False

    def repair_hive_table(self):
        """Execute a MSCK REPAIR TABLE on a given Athena table"""
        athena_config = self.config['lambda']['athena_partition_refresh_config']
        repair_hive_table_config = athena_config['refresh_type']['repair_hive_table']

        for athena_table in repair_hive_table_config.itervalues():
            query_success, query_resp = self.run_athena_query(
                query='MSCK REPAIR TABLE {};'.format(athena_table),
                database=self.DATABASE_STREAMALERT
            )
            if query_success:
                LOGGER.info('Query results:')
                for row in query_resp['ResultSet']['Rows']:
                    LOGGER.info(row['Data'])
            else:
                logger.error('Partition refresh of the Athena table '
                             '%s has failed.', athena_table)

    @staticmethod
    def firehose_partition_refresh(_):
        """Execute a Firehose specific partition update"""
        LOGGER.error('Firehose partition refresh is not yet supported, exiting!')
        raise NotImplementedError


def handler(event, _):
    """Athena Partition Refresher Handler Function"""
    stream_alert_athena = StreamAlertAthenaClient()

    # The StreamAlert database needs to exist before we run queries.
    if not stream_alert_athena.check_database_exists():
        return

    stream_alert_athena.repair_hive_table()

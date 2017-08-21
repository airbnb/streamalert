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
import json
import logging
import os

import backoff
import boto3

logging.basicConfig(format='%(name)s [%(levelname)s]: [%(module)s.%(funcName)s] %(message)s')
LEVEL = os.environ.get('LOGGER_LEVEL', 'INFO')
LOGGER = logging.getLogger('StreamAlertAthena')
LOGGER.setLevel(LEVEL.upper())


def _backoff_handler(details):
    """Backoff logging handler for when polling occurs.

    Args:
        details (dict): Backoff context containing the number of tries,
            target function currently executing, kwargs, args, value,
            and wait time.
    """
    LOGGER.debug('[Backoff]: Trying again in %f seconds after %d tries calling %s',
                 details['wait'],
                 details['tries'],
                 details['target'].__name__)


def _success_handler(details):
    """Backoff logging handler for when backoff succeeds.

    Args:
        details (dict): Backoff context containing the number of tries,
            target function currently executing, kwargs, args, value,
            and wait time.
    """
    LOGGER.debug('[Backoff]: Completed after %d tries calling %s',
                 details['tries'],
                 details['target'].__name__)


def _load_config():
    """Load the StreamAlert Athena configuration files

    Returns:
        dict: Configuration settings by file, includes two keys:
            lambda, All lambda function settings
            global, StreamAlert global settings

    Raises:
        ConfigError: For invalid or missing configuration files.
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


class ConfigError(Exception):
    """Custom StreamAlertAthena Config Exception Class"""
    pass


class AthenaPartitionRefreshError(Exception):
    """Generic Athena Partition Error for erroring the Lambda function"""
    pass


class StreamAlertAthenaClient(object):
    """A StreamAlert Athena Client for creating tables, databases, and executing queries

    Attributes:
        config: The loaded StreamAlert configuration
        athena_client: Boto3 Athena client
        athena_results_bucket: The S3 bucket to store Athena query results
        athenea_results_key: The key in S3 to store Athena query results
    """
    DATABASE_DEFAULT = 'default'
    DATABASE_STREAMALERT = 'streamalert'
    DEFAULT_S3_PREFIX = 'athena_partition_refresh'

    def __init__(self, config, **kwargs):
        """Initialize the Boto3 Athena Client, and S3 results bucket/key

        Args:
            config (CLIConfig): Loaded StreamAlert configuration

        Keyword Args:
            results_key_prefix (str): The S3 key prefix to store Athena results
        """
        self.config = config
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

    def check_query_status(self, query_execution_id):
        """Check in on the running query, back off if the job is running or queued

        Args:
            query_execution_id (str): The Athena query execution ID

        Returns:
            str: The result of the Query.  This value can be SUCCEEDED, FAILED, or CANCELLED.
                Reference https://bit.ly/2uuRtda.
        """
        @backoff.on_predicate(backoff.fibo,
                              lambda status: status in ('QUEUED', 'RUNNING'),
                              max_value=10,
                              jitter=backoff.full_jitter,
                              on_backoff=_backoff_handler,
                              on_success=_success_handler)
        def _get_query_execution(query_execution_id):
            return self.athena_client.get_query_execution(
                QueryExecutionId=query_execution_id
            )['QueryExecution']['Status']['State']

        return _get_query_execution(query_execution_id)

    def run_athena_query(self, **kwargs):
        """Helper function to run Athena queries

        Keyword Args:
            query (str): The SQL query to execute
            database (str): The database context to execute the query in

        Returns:
            bool, dict: query success, query result response
        """
        LOGGER.debug('Executing query: %s', kwargs['query'])
        query_execution_resp = self.athena_client.start_query_execution(
            QueryString=kwargs['query'],
            QueryExecutionContext={'Database': kwargs.get('database', self.DATABASE_DEFAULT)},
            ResultConfiguration={
                'OutputLocation': '{}/{}'.format(
                    self.athena_results_bucket, self.athena_results_key)
            }
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
        """Verify the StreamAlert Athena database exists.

        Keyword Args:
            database (str): The database name to execute the query under
        """
        database = kwargs.get('database', self.DATABASE_STREAMALERT)
        query_success, query_resp = self.run_athena_query(
            query='SHOW DATABASES LIKE \'{}\';'.format(database),
        )

        if query_success and query_resp['ResultSet']['Rows']:
            return True

        LOGGER.error('The \'%s\' database does not exist. '
                     'Create it with the following command: \n'
                     '$ python manage.py athena create-db',
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

        LOGGER.info('The streamalert table \'%s\' does not exist. '
                    'For alert buckets, create it with the following command: \n'
                    '$ python manage.py athena create-table '
                    '--type alerts --bucket s3.bucket.id',
                    table_name)
        return False

    def repair_hive_table(self, unique_buckets):
        """Execute a MSCK REPAIR TABLE on a given Athena table"""
        athena_config = self.config['lambda']['athena_partition_refresh_config']
        repair_hive_table_config = athena_config['refresh_type']['repair_hive_table']

        for data_bucket in unique_buckets:
            athena_table = repair_hive_table_config.get(data_bucket)
            if not athena_table:
                LOGGER.warning('%s not found in repair_hive_table config. '
                               'Please update your configuration accordingly.',
                               athena_table)
                continue

            query_success, query_resp = self.run_athena_query(
                query='MSCK REPAIR TABLE {};'.format(athena_table),
                database=self.DATABASE_STREAMALERT
            )

            if query_success:
                LOGGER.info('Query results:')
                for row in query_resp['ResultSet']['Rows']:
                    LOGGER.info(row['Data'])
            else:
                LOGGER.error('Partition refresh of the Athena table '
                             '%s has failed.', athena_table)
                return False

        return True

    @staticmethod
    def add_hive_partition(_):
        """Execute a Hive Add Partition command on a given Athena table"""
        LOGGER.error('Add Hive Parition is not yet supported, exiting!')
        raise NotImplementedError


class StreamAlertSQSClient(object):
    """A StreamAlert SQS Client for polling and deleting S3 event notifications

    Attributes:
        config: The loaded StreamAlert configuration
        sqs_client: The Boto3 SQS client
        athena_sqs_url: The URL to the Athena SQS Queue
        received_messages: A list of receieved SQS messages
        processed_messages: A list of processed SQS messages
    """
    QUEUENAME = 'streamalert_athena_data_bucket_notifications'

    def __init__(self, config):
        """Initialize the StreamAlertSQS Client

        Args:
            config (CLIConfig): Loaded StreamAlert configuration
        """
        self.config = config
        self.received_messages = []
        self.processed_messages = []

        self.setup()

    def setup(self):
        """Get the SQS URL for Athena bucket s3 notifications"""
        region = self.config['global']['account']['region']
        self.sqs_client = boto3.client('sqs', region_name=region)

        self.athena_sqs_url = self.sqs_client.list_queues(
            QueueNamePrefix=self.QUEUENAME
        )['QueueUrls'][0]

    def get_messages(self):
        """Poll the queue for messages"""
        @backoff.on_predicate(backoff.fibo,
                              # Backoff up to 5 times
                              max_tries=5,
                              # Don't backoff for longer than 5 seconds
                              # This constrains the total max backoff to 25 seconds
                              max_value=5,
                              jitter=backoff.full_jitter,
                              on_backoff=_backoff_handler,
                              on_success=_success_handler)
        def _receive_messages():
            polled_messages = self.sqs_client.receive_message(
                QueueUrl=self.athena_sqs_url,
                MaxNumberOfMessages=10
            )

            if 'Messages' not in polled_messages:
                return False
            self.received_messages.extend(polled_messages['Messages'])

        _receive_messages()
        LOGGER.info('Received %s messages', len(self.received_messages))

    def delete_messages(self):
        """Delete messages off the queue once processed"""
        if not self.processed_messages:
            LOGGER.error('No processed messages to delete')
            return

        while self.processed_messages:
            len_processed_messages = len(self.processed_messages)
            batch = len_processed_messages if len_processed_messages < 10 else 10

            # Delete_batch can only process up to 10 messages
            message_batch = [self.processed_messages.pop() for _ in range(batch)]

            resp = self.sqs_client.delete_message_batch(
                QueueUrl=self.athena_sqs_url,
                Entries=[{'Id': message['MessageId'],
                          'ReceiptHandle': message['ReceiptHandle']}
                         for message in message_batch]
            )
            LOGGER.info('Successfully deleted %s messages from the queue',
                        len(resp['Successful']))

    def unique_buckets_from_messages(self):
        """Filter a list of unique s3 buckets from the received messages

        Returns:
            set: Unique s3 buckets derived from s3 event notifications
        """
        buckets = set()

        if not self.received_messages:
            LOGGER.error('No messages to filter, fetch the messages with get_messages()')
            return

        for message in self.received_messages:
            if 'Body' not in message:
                LOGGER.error('Missing `Body` key, trying next SQS message')
                continue

            loaded_message = json.loads(message['Body'])

            if 'Records' not in loaded_message:
                LOGGER.error('Missing `Records` key, trying next SQS message')
                continue

            for record in loaded_message['Records']:
                if 's3' not in record:
                    LOGGER.info('Skipping non-s3 bucket notification message')
                    LOGGER.debug(record)
                    continue

                buckets.add(record['s3']['bucket']['name'])
                # Add to a new list to denote processed messages
                self.processed_messages.append(message)

        return buckets


def handler(*_):
    """Athena Partition Refresher Handler Function"""
    config = _load_config()

    # Initialize the SQS client and recieve messages
    stream_alert_sqs = StreamAlertSQSClient(config)
    stream_alert_sqs.get_messages()

    if not stream_alert_sqs.received_messages:
        LOGGER.info('No messages recieved, exiting')
        return

    unique_buckets = stream_alert_sqs.unique_buckets_from_messages()
    if not unique_buckets:
        LOGGER.error('No s3 buckets to refresh, exiting')
        return

    # Initialize the Athena client and run queries
    stream_alert_athena = StreamAlertAthenaClient(config)

    # Check that the `streamalert` database exists before running queries
    if not stream_alert_athena.check_database_exists():
        raise AthenaPartitionRefreshError('The `streamalert` database does not exist')

    if not stream_alert_athena.repair_hive_table(unique_buckets):
        raise AthenaPartitionRefreshError('Partiton refresh has failed')

    stream_alert_sqs.delete_messages()

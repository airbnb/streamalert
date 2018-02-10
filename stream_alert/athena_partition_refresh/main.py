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
from collections import defaultdict
from datetime import datetime
import json
import os
import re
import urllib

import backoff
import boto3

from stream_alert.athena_partition_refresh import LOGGER


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


def _giveup_handler(details):
    """Backoff logging handler for when backoff gives up.

    Args:
        details (dict): Backoff context containing the number of tries,
            target function currently executing, kwargs, args, value,
            and wait time.
    """
    LOGGER.debug('[Backoff]: Exiting after %d tries calling %s',
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


class AthenaPartitionRefreshError(Exception):
    """Generic Athena Partition Error for erroring the Lambda function"""


class StreamAlertAthenaClient(object):
    """A StreamAlert Athena Client for creating tables, databases, and executing queries

    Attributes:
        config: The loaded StreamAlert configuration
        athena_client: Boto3 Athena client
        athena_results_bucket: The S3 bucket to store Athena query results
        athenea_results_key: The key in S3 to store Athena query results
    """
    DATABASE_DEFAULT = 'default'
    DEFAULT_DATABASE_STREAMALERT = '{}_streamalert'
    DEFAULT_S3_PREFIX = 'athena_partition_refresh'

    STREAMALERTS_REGEX = re.compile(r'alerts/dt=(?P<year>\d{4})'
                                    r'\-(?P<month>\d{2})'
                                    r'\-(?P<day>\d{2})'
                                    r'\-(?P<hour>\d{2})'
                                    r'\/.*.json')
    FIREHOSE_REGEX = re.compile(r'(?P<year>\d{4})'
                                r'\/(?P<month>\d{2})'
                                r'\/(?P<day>\d{2})'
                                r'\/(?P<hour>\d{2})\/.*')

    def __init__(self, config, **kwargs):
        """Initialize the Boto3 Athena Client, and S3 results bucket/key

        Args:
            config (CLIConfig): Loaded StreamAlert configuration

        Keyword Args:
            results_key_prefix (str): The S3 key prefix to store Athena results
        """
        self.config = config
        self.prefix = self.config['global']['account']['prefix']

        region = self.config['global']['account']['region']
        self.athena_client = boto3.client('athena', region_name=region)

        athena_config = self.config['lambda']['athena_partition_refresh_config']

        # GEt the S3 bucket to store Athena query results
        results_bucket = athena_config.get('results_bucket', '').strip()
        if results_bucket == '':
            self.athena_results_bucket = 's3://{}.streamalert.athena-results'.format(self.prefix)
        elif results_bucket[:5] != 's3://':
            self.athena_results_bucket = 's3://{}'.format(results_bucket)
        else:
            self.athena_results_bucket = results_bucket

        # Format the S3 key to store specific objects
        results_key_prefix = kwargs.get('results_key_prefix', self.DEFAULT_S3_PREFIX)
        # Produces athena_partition_refresh/YYYY/MM/DD S3 keys
        self.athena_results_key = os.path.join(
            results_key_prefix,
            datetime.now().strftime('%Y/%m/%d'))

    @property
    def sa_database(self):
        """Return the name of the streamalert database. This can be overridden in the config"""
        database = self.config['lambda']['athena_partition_refresh_config'].get('database_name', '')
        database = database.replace(' ', '') # strip any spaces which are invalid database names
        if database == '':
            return self.DEFAULT_DATABASE_STREAMALERT.format(self.prefix)

        return database

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
            async (bool): If the function should asynchronously run queries
                without backing off until completion.

        Returns:
            bool, dict: query success, query result response
        """
        LOGGER.debug('Executing query: %s', kwargs['query'])
        query_execution_resp = self.athena_client.start_query_execution(
            QueryString=kwargs['query'],
            QueryExecutionContext={'Database': kwargs.get('database', self.DATABASE_DEFAULT)},
            ResultConfiguration={'OutputLocation': '{}/{}'.format(self.athena_results_bucket,
                                                                  self.athena_results_key)})

        # If asynchronous invocation is enabled, and a valid query
        # execution ID was returned.
        if kwargs.get('async') and query_execution_resp.get('QueryExecutionId'):
            return True, query_execution_resp

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
        database = kwargs.get('database', self.sa_database)
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
            database=self.sa_database
        )

        if query_success and query_resp['ResultSet']['Rows']:
            return True

        LOGGER.info('The streamalert table \'%s\' does not exist.', table_name)
        LOGGER.info('For help with creating tables: '
                    '$ python manage.py athena create-table --help')
        return False

    def repair_hive_table(self, unique_buckets):
        """Execute a MSCK REPAIR TABLE on a given Athena table

        Args:
            unique_buckets (list): S3 buckets to repair

        Returns:
            (bool): If the repair was successful for not
        """
        athena_config = self.config['lambda']['athena_partition_refresh_config']
        repair_hive_table_config = athena_config['refresh_type']['repair_hive_table']

        LOGGER.info('Processing Hive repair table...')
        for data_bucket in unique_buckets:
            athena_table = repair_hive_table_config.get(data_bucket)
            if not athena_table:
                LOGGER.warning('%s not found in repair_hive_table config. '
                               'Please update your configuration accordingly.',
                               athena_table)
                continue

            query_success, query_resp = self.run_athena_query(
                query='MSCK REPAIR TABLE {};'.format(athena_table),
                database=self.sa_database
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

    def add_hive_partition(self, s3_buckets_and_keys):
        """Execute a Hive Add Partition command on a given Athena table

        Args:
            s3_buckets_and_keys (dict): Buckets and unique keys to add partitions

        Returns:
            (bool): If the repair was successful for not
        """
        athena_config = self.config['lambda']['athena_partition_refresh_config']
        add_hive_partition_config = athena_config['refresh_type']['add_hive_partition']
        partitions = defaultdict(dict)

        LOGGER.info('Processing new Hive partitions...')
        for bucket, keys in s3_buckets_and_keys.iteritems():
            athena_table = add_hive_partition_config.get(bucket)
            if not athena_table:
                # TODO(jacknagz): Add this as a metric
                LOGGER.error('%s not found in \'add_hive_partition\' config. '
                             'Please add this bucket to enable additions '
                             'of Hive partitions.',
                             athena_table)
                continue

            # Iterate over each key
            for key in keys:
                for pattern in (self.FIREHOSE_REGEX, self.STREAMALERTS_REGEX):
                    match = pattern.search(key)
                    if match:
                        break

                if not match:
                    LOGGER.error('The key %s does not match any regex, skipping', key)
                    continue

                # Convert the match groups to a dict for easy access
                match_dict = match.groupdict()
                # Get the path to the objects in S3
                path = os.path.dirname(key)
                # The config does not need to store all possible tables
                # for enabled log types because this can be inferred from
                # the incoming S3 bucket notification.  Only enabled
                # log types will be sending data to Firehose.
                # This logic extracts out the name of the table from the
                # first element in the S3 path, as that's how log types
                # are configured to send to Firehose.
                if athena_table != 'alerts':
                    athena_table = path.split('/')[0]

                # Example:
                # PARTITION (dt = '2017-01-01-01') LOCATION 's3://bucket/path/'
                partition = '(dt = \'{year}-{month}-{day}-{hour}\')'.format(
                    year=match_dict['year'],
                    month=match_dict['month'],
                    day=match_dict['day'],
                    hour=match_dict['hour'])
                location = '\'s3://{bucket}/{path}\''.format(
                    bucket=bucket,
                    path=path)
                # By using the partition as the dict key, this ensures that
                # Athena will not try to add the same partition twice.
                # TODO(jacknagz): Write this dictionary to SSM/DynamoDb
                # to increase idempotence of this Lambda function
                partitions[athena_table][partition] = location

        if not partitions:
            LOGGER.error('No partitons to add')
            return False

        for athena_table in partitions:
            partition_statement = ' '.join(
                ['PARTITION {0} LOCATION {1}'.format(
                    partition, location) for partition, location
                 in partitions[athena_table].iteritems()])
            query = ('ALTER TABLE {athena_table} '
                     'ADD IF NOT EXISTS {partition_statement};'.format(
                         athena_table=athena_table,
                         partition_statement=partition_statement))

            query_success, _ = self.run_athena_query(
                query=query,
                database=self.sa_database
            )

            if not query_success:
                raise AthenaPartitionRefreshError(
                    'The add hive partition query has failed:\n{}'.format(query)
                )

            LOGGER.info('Successfully added the following partitions:\n%s',
                        json.dumps({athena_table: partitions[athena_table]}, indent=4))
        return True


class StreamAlertSQSClient(object):
    """A StreamAlert SQS Client for polling and deleting S3 event notifications

    Attributes:
        config: The loaded StreamAlert configuration
        sqs_client: The Boto3 SQS client
        athena_sqs_url: The URL to the Athena SQS Queue
        received_messages: A list of receieved SQS messages
        processed_messages: A list of processed SQS messages
    """
    DEFAULT_QUEUE_NAME = '{}_streamalert_athena_data_bucket_notifications'
    MAX_SQS_GET_MESSAGE_COUNT = 10

    def __init__(self, config):
        """Initialize the StreamAlertSQS Client

        Args:
            config (CLIConfig): Loaded StreamAlert configuration
        """
        self.config = config
        self.received_messages = []
        self.processed_messages = []
        self.deleted_messages = 0

        self.setup()

    @property
    def queue_name(self):
        """Return the name of the sqs queue to use. This can be overridden in the config"""
        queue = self.config['lambda']['athena_partition_refresh_config'].get('queue_name', '')
        queue = queue.replace(' ', '') # strip any spaces which are invalid queue names
        if queue == '':
            prefix = self.config['global']['account']['prefix']
            return self.DEFAULT_QUEUE_NAME.format(prefix)

        return queue

    def setup(self):
        """Get the SQS URL for Athena bucket s3 notifications"""
        region = self.config['global']['account']['region']
        self.sqs_client = boto3.client('sqs', region_name=region)

        self.athena_sqs_url = self.sqs_client.list_queues(
            QueueNamePrefix=self.queue_name
        )['QueueUrls'][0]

    def get_messages(self, **kwargs):
        """Poll the SQS queue for new messages

        Keyword Args:
            max_tries (int): The number of times to backoff
            max_value (int): The max wait interval between backoffs
            max_messages (int): The max number of messages to get from SQS
        """
        start_message_count = len(self.received_messages)

        # Backoff up to 5 times to limit the time spent in this operation
        # relative to the entire Lambda duration.
        max_tries = kwargs.get('max_tries', 5)

        # This value restricts the max time of backoff each try.
        # This means the total backoff time for one function call is:
        #   max_tries (attempts) * max_value (seconds)
        max_value = kwargs.get('max_value', 5)

        # Number of messages to poll from the stream.
        max_messages = kwargs.get('max_messages', self.MAX_SQS_GET_MESSAGE_COUNT)
        if max_messages > self.MAX_SQS_GET_MESSAGE_COUNT:
            LOGGER.error('SQS can only request up to 10 messages in one request')
            return

        @backoff.on_predicate(backoff.fibo,
                              max_tries=max_tries,
                              max_value=max_value,
                              jitter=backoff.full_jitter,
                              on_backoff=_backoff_handler,
                              on_success=_success_handler,
                              on_giveup=_giveup_handler)
        def _receive_messages():
            polled_messages = self.sqs_client.receive_message(
                QueueUrl=self.athena_sqs_url,
                MaxNumberOfMessages=max_messages
            )

            if 'Messages' not in polled_messages:
                return False
            self.received_messages.extend(polled_messages['Messages'])

        _receive_messages()
        batch_count = len(self.received_messages) - start_message_count
        LOGGER.info('Received %d message(s) from SQS', batch_count)

    def delete_messages(self):
        """Delete messages off the queue once processed"""
        if not self.processed_messages:
            LOGGER.error('No processed messages to delete')
            return

        @backoff.on_predicate(backoff.fibo,
                              lambda len_messages: len_messages > 0,
                              max_value=10,
                              jitter=backoff.full_jitter,
                              on_backoff=_backoff_handler,
                              on_success=_success_handler)
        def _delete_messages_from_queue():
            # Determine the message batch for SQS message deletion
            len_processed_messages = len(self.processed_messages)
            batch = len_processed_messages if len_processed_messages < 10 else 10
            # Pop processed records from the list to be deleted
            message_batch = [self.processed_messages.pop() for _ in range(batch)]

            # This debug info should be removed when Issue #590 is fixed.
            # https://github.com/airbnb/streamalert/issues/590
            LOGGER.debug('The messages to be deleted: \n%s', message_batch)

            # Try to delete the batch
            resp = self.sqs_client.delete_message_batch(
                QueueUrl=self.athena_sqs_url,
                Entries=[{'Id': message['MessageId'],
                          'ReceiptHandle': message['ReceiptHandle']}
                         for message in message_batch])

            # Handle successful deletions
            if resp.get('Successful'):
                self.deleted_messages += len(resp['Successful'])
            # Handle failure deletion
            if resp.get('Failed'):
                LOGGER.error(('Failed to delete the messages with following (%d) '
                              'error messages:\n%s'),
                             len(resp['Failed']), json.dumps(resp['Failed']))
                # Add the failed messages back to the processed_messages attribute
                # to be retried via backoff
                self.processed_messages.extend([[message
                                                 for message
                                                 in message_batch
                                                 if message['MessageId'] == failed_message['Id']]
                                                for failed_message in resp['Failed']])

            return len(self.processed_messages)

        _delete_messages_from_queue()

    def unique_s3_buckets_and_keys(self):
        """Filter a list of unique s3 buckets and S3 keys from event notifications

        Returns:
            (dict): Keys of bucket names, and values of unique S3 keys
        """
        s3_buckets_and_keys = defaultdict(set)

        if not self.received_messages:
            LOGGER.error('No messages to filter, fetch the messages with get_messages()')
            return

        for message in self.received_messages:
            if 'Body' not in message:
                LOGGER.error('Missing \'Body\' key in SQS message, skipping')
                continue

            loaded_message = json.loads(message['Body'])

            # From AWS documentation: http://amzn.to/2w4fcSq
            # When you configure an event notification on a bucket,
            # Amazon S3 sends the following test message:
            # {
            #    "Service":"Amazon S3",
            #    "Event":"s3:TestEvent",
            #    "Time":"2014-10-13T15:57:02.089Z",
            #    "Bucket":"bucketname",
            #    "RequestId":"5582815E1AEA5ADF",
            #    "HostId":"8cLeGAmw098X5cv4Zkwcmo8vvZa3eH3eKxsPzbB9wrR+YstdA6Knx4Ip8EXAMPLE"
            # }
            if loaded_message.get('Event') == 's3:TestEvent':
                LOGGER.debug('Skipping S3 bucket notification test event')
                continue

            if 'Records' not in loaded_message:
                LOGGER.error('Missing \'Records\' key in SQS message, skipping:\n%s',
                             json.dumps(loaded_message, indent=4))
                continue

            for record in loaded_message['Records']:
                if 's3' not in record:
                    LOGGER.info('Skipping non-s3 bucket notification message')
                    LOGGER.debug(record)
                    continue

                bucket_name = record['s3']['bucket']['name']
                # Account for special characters in the S3 object key
                # Example: Usage of '=' in the key name
                object_key = urllib.unquote(record['s3']['object']['key']).decode('utf8')
                s3_buckets_and_keys[bucket_name].add(object_key)

                # Add to a new list to track successfully processed messages from the queue
                self.processed_messages.append(message)

        return s3_buckets_and_keys


def handler(*_):
    """Athena Partition Refresher Handler Function"""
    config = _load_config()

    # Initialize the SQS client and recieve messages
    stream_alert_sqs = StreamAlertSQSClient(config)
    # Get the first batch of messages from SQS.  If there are no
    # messages, this will exit early.
    stream_alert_sqs.get_messages(max_tries=2)

    if not stream_alert_sqs.received_messages:
        LOGGER.info('No SQS messages recieved, exiting')
        return

    # If the max amount of messages was initially returned,
    # then get the next batch of messages.  The max is determined based
    # on (number of tries) * (number of possible max messages returned)
    if len(stream_alert_sqs.received_messages) == 20:
        stream_alert_sqs.get_messages(max_tries=8)

    s3_buckets_and_keys = stream_alert_sqs.unique_s3_buckets_and_keys()
    if not s3_buckets_and_keys:
        LOGGER.error('No new Athena partitions to add, exiting')
        return

    # Initialize the Athena client and run queries
    stream_alert_athena = StreamAlertAthenaClient(config)

    # Check that the 'streamalert' database exists before running queries
    if not stream_alert_athena.check_database_exists():
        raise AthenaPartitionRefreshError(
            'The \'{}\' database does not exist'.format(stream_alert_athena.sa_database)
        )

    if not stream_alert_athena.add_hive_partition(s3_buckets_and_keys):
        LOGGER.error('Failed to add hive partition(s)')
        return

    stream_alert_sqs.delete_messages()
    LOGGER.info('Deleted %d messages from SQS',
                stream_alert_sqs.deleted_messages)

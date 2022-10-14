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
import json
import posixpath
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict

from streamalert.shared.athena import AthenaClient
from streamalert.shared.config import athena_partition_buckets, load_config
from streamalert.shared.exceptions import ConfigError
from streamalert.shared.logger import get_logger
from streamalert.shared.utils import get_data_file_format, get_database_name

LOGGER = get_logger(__name__)


class AthenaPartitionerError(Exception):
    """Generic Athena Partition Error for erroring the Lambda function"""


class AthenaPartitioner:
    """Handle polling an SQS queue and running Athena queries for updating tables"""

    ALERTS_REGEX = re.compile(r'alerts/dt=(?P<year>\d{4})'
                              r'\-(?P<month>\d{2})'
                              r'\-(?P<day>\d{2})'
                              r'\-(?P<hour>\d{2})'
                              r'\/.*.json')
    DATA_REGEX = re.compile(r'(?P<year>\d{4})'
                            r'\/(?P<month>\d{2})'
                            r'\/(?P<day>\d{2})'
                            r'\/(?P<hour>\d{2})\/.*')

    ALERTS_REGEX_PARQUET = re.compile(r'alerts/dt=(?P<year>\d{4})'
                                      r'\-(?P<month>\d{2})'
                                      r'\-(?P<day>\d{2})'
                                      r'\-(?P<hour>\d{2})'
                                      r'\/.*.parquet')
    DATA_REGEX_PARQUET = re.compile(r'dt=(?P<year>\d{4})'
                                    r'\-(?P<month>\d{2})'
                                    r'\-(?P<day>\d{2})'
                                    r'\-(?P<hour>\d{2})\/.*')

    ATHENA_S3_PREFIX = 'athena_partitioner'

    _ATHENA_CLIENT = None

    def __init__(self):
        config = load_config(include={'lambda.json', 'global.json'})
        prefix = config['global']['account']['prefix']
        athena_config = config['lambda']['athena_partitioner_config']
        self._file_format = get_data_file_format(config)

        if self._file_format == 'parquet':
            self._alerts_regex = self.ALERTS_REGEX_PARQUET
            self._data_regex = self.DATA_REGEX_PARQUET

        elif self._file_format == 'json':
            self._alerts_regex = self.ALERTS_REGEX
            self._data_regex = self.DATA_REGEX
        else:
            message = (
                f'file format "{self._file_format}" is not supported. Supported file format are "parquet", "json". '
                f'Please update the setting in athena_partitioner_config in "conf/lambda.json"')
            raise ConfigError(message)

        self._athena_buckets = athena_partition_buckets(config)

        db_name = get_database_name(config)

        # Get the S3 bucket to store Athena query results
        results_bucket = athena_config.get('results_bucket',
                                           f's3://{prefix}-streamalert-athena-results')

        self._s3_buckets_and_keys = defaultdict(set)

        self._create_client(db_name, results_bucket)

    @classmethod
    def _create_client(cls, db_name, results_bucket):
        if cls._ATHENA_CLIENT:
            return  # Client already created/cached

        cls._ATHENA_CLIENT = AthenaClient(db_name, results_bucket, cls.ATHENA_S3_PREFIX)

        # Check if the database exists when the client is created
        if not cls._ATHENA_CLIENT.check_database_exists():
            raise AthenaPartitionerError(f"The \'{db_name}\' database does not exist")

    def _get_partitions_from_keys(self):
        """Get the partitions that need to be added for the Athena tables

        Returns:
            (dict): representation of tables, partitions and locations to be added
                Example:
                    {
                        'alerts': {
                            '(dt = \'2018-08-01-01\')': 's3://streamalert.alerts/2018/08/01/01'
                        }
                    }
        """
        partitions = defaultdict(dict)

        LOGGER.info('Processing new Hive partitions...')
        for bucket, keys in self._s3_buckets_and_keys.items():
            athena_table = self._athena_buckets.get(bucket)
            if not athena_table:
                # TODO(jacknagz): Add this as a metric
                LOGGER.error(
                    '\'%s\' not found in \'buckets\' config. Please add this '
                    'bucket to enable additions of Hive partitions.', bucket)
                continue

            # Iterate over each key
            for key in keys:
                match = None
                key = key.decode('utf-8')
                for pattern in (self._data_regex, self._alerts_regex):
                    match = pattern.search(key)
                    if match:
                        break

                if not match:
                    LOGGER.warning('The key %s does not match any regex, skipping', key)
                    continue

                # Get the path to the objects in S3
                path = posixpath.dirname(key)
                # The config does not need to store all possible tables
                # for enabled log types because this can be inferred from
                # the incoming S3 bucket notification.  Only enabled
                # log types will be sending data to Firehose.
                # This logic extracts out the name of the table from the
                # first element in the S3 path, as that's how log types
                # are configured to send to Firehose.
                if athena_table != 'alerts':
                    athena_table = (
                        # when file_format is json, s3 file path is
                        #   s3://bucketname/[data-type]/YYYY/MM/DD/hh/*.gz
                        # when file_format is parquet, s3 file path is
                        #   s3://bucketname/parquet/[data-type]/dt=YYYY-MM-DD-hh/*.parquet
                        path.split('/')[1]
                        if self._file_format == 'parquet' else path.split('/')[0])

                # Example:
                # PARTITION (dt = '2017-01-01-01') LOCATION 's3://bucket/path/'
                partition = '(dt = \'{year}-{month}-{day}-{hour}\')'.format(**match.groupdict())
                location = f'\'s3://{bucket}/{path}\''
                # By using the partition as the dict key, this ensures that
                # Athena will not try to add the same partition twice.
                # TODO(jacknagz): Write this dictionary to SSM/DynamoDB
                # to increase idempotence of this Lambda function
                partitions[athena_table][partition] = location

        return partitions

    def _add_partitions(self):
        """Execute a Hive Add Partition command for the given Athena tables and partitions

        Returns:
            (bool): If the repair was successful for not
        """
        partitions = self._get_partitions_from_keys()
        if not partitions:
            LOGGER.warning('No partitions to add')
            return False

        for athena_table in partitions:
            partition_statement = ' '.join([
                f'PARTITION {partition} LOCATION {location}'
                for partition, location in partitions[athena_table].items()
            ])
            query = ('ALTER TABLE {athena_table} '
                     'ADD IF NOT EXISTS {partition_statement};'.format(
                         athena_table=athena_table, partition_statement=partition_statement))

            if  self._ATHENA_CLIENT.run_query(query=query):
                LOGGER.info('Successfully added the following partitions:\n%s',
                            json.dumps({athena_table: partitions[athena_table]}))
            else:
                raise AthenaPartitionerError(f'The add hive partition query has failed:\n{query}')

        return True

    def run(self, event):
        """Take the messages from the SQS queue and create partitions for new data in S3

        Args:
            event (dict): Lambda input event containing SQS messages. Each SQS message
                should contain one (or maybe more) S3 bucket notification message.
        """
        # Check that the database being used exists before running queries
        for sqs_rec in event['Records']:
            LOGGER.debug('Processing event with message ID \'%s\' and SentTimestamp %s',
                         sqs_rec['messageId'], sqs_rec['attributes']['SentTimestamp'])

            body = json.loads(sqs_rec['body'])
            if body.get('Event') == 's3:TestEvent':
                LOGGER.debug('Skipping S3 bucket notification test event')
                continue

            for s3_rec in body['Records']:
                if 's3' not in s3_rec:
                    LOGGER.info('Skipping non-s3 bucket notification message: %s', s3_rec)
                    continue

                bucket_name = s3_rec['s3']['bucket']['name']

                # Account for special characters in the S3 object key
                # Example: Usage of '=' in the key name
                object_key = urllib.parse.unquote_plus(s3_rec['s3']['object']['key']).encode()
                if object_key.endswith(b'_$folder$'):
                    LOGGER.info('Skipping placeholder file notification with key: %s', object_key)
                    continue

                LOGGER.debug('Received notification for object \'%s\' in bucket \'%s\'', object_key,
                             bucket_name)

                self._s3_buckets_and_keys[bucket_name].add(object_key)
        self._add_partitions()


def handler(event, _):
    """Athena Partitioner Handler Function"""
    AthenaPartitioner().run(event)

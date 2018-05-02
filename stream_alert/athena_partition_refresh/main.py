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
from __future__ import absolute_import  # Suppresses RuntimeWarning import error in Lambda
from collections import defaultdict
import json
import posixpath
import re

from stream_alert.athena_partition_refresh.clients import StreamAlertSQSClient

from stream_alert.athena_partition_refresh import LOGGER
from stream_alert.shared.athena import StreamAlertAthenaClient
from stream_alert.shared.config import load_config


class AthenaRefreshError(Exception):
    """Generic Athena Partition Error for erroring the Lambda function"""


class AthenaRefresher(object):
    """Handle polling an SQS queue and running Athena queries for updating tables"""

    STREAMALERTS_REGEX = re.compile(r'alerts/dt=(?P<year>\d{4})'
                                    r'\-(?P<month>\d{2})'
                                    r'\-(?P<day>\d{2})'
                                    r'\-(?P<hour>\d{2})'
                                    r'\/.*.json')
    FIREHOSE_REGEX = re.compile(r'(?P<year>\d{4})'
                                r'\/(?P<month>\d{2})'
                                r'\/(?P<day>\d{2})'
                                r'\/(?P<hour>\d{2})\/.*')

    STREAMALERT_DATABASE = '{}_streamalert'
    ATHENA_S3_PREFIX = 'athena_partition_refresh'

    def __init__(self):
        config = load_config(include={'lambda.json', 'global.json'})
        prefix = config['global']['account']['prefix']
        athena_config = config['lambda']['athena_partition_refresh_config']

        self._athena_buckets = athena_config['buckets']

        db_name = athena_config.get(
            'database_name',
            self.STREAMALERT_DATABASE.format(prefix)
        ).strip()

        # Get the S3 bucket to store Athena query results
        results_bucket = athena_config.get(
            'results_bucket',
            's3://{}.streamalert.athena-results'.format(prefix)
        ).strip()

        self._athena_client = StreamAlertAthenaClient(
            db_name,
            results_bucket,
            self.ATHENA_S3_PREFIX
        )

        # Initialize the SQS client and recieve messages
        self._sqs_client = StreamAlertSQSClient(config)

    def _get_partitions_from_keys(self, s3_buckets_and_keys):
        partitions = defaultdict(dict)

        LOGGER.info('Processing new Hive partitions...')
        for bucket, keys in s3_buckets_and_keys.iteritems():
            athena_table = self._athena_buckets.get(bucket)
            if not athena_table:
                # TODO(jacknagz): Add this as a metric
                LOGGER.error('%s not found in \'buckets\' config. Please add this '
                             'bucket to enable additions of Hive partitions.',
                             athena_table)
                continue

            # Iterate over each key
            for key in keys:
                match = None
                for pattern in (self.FIREHOSE_REGEX, self.STREAMALERTS_REGEX):
                    match = pattern.search(key)
                    if match:
                        break

                if not match:
                    LOGGER.error('The key %s does not match any regex, skipping', key)
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
                    athena_table = path.split('/')[0]

                # Example:
                # PARTITION (dt = '2017-01-01-01') LOCATION 's3://bucket/path/'
                partition = '(dt = \'{year}-{month}-{day}-{hour}\')'.format(**match.groupdict())
                location = '\'s3://{bucket}/{path}\''.format(bucket=bucket, path=path)
                # By using the partition as the dict key, this ensures that
                # Athena will not try to add the same partition twice.
                # TODO(jacknagz): Write this dictionary to SSM/DynamoDb
                # to increase idempotence of this Lambda function
                partitions[athena_table][partition] = location

        return partitions

    def _add_partition(self, s3_buckets_and_keys):
        """Execute a Hive Add Partition command on a given Athena table

        Args:
            s3_buckets_and_keys (dict): Buckets and unique keys to add partitions

        Returns:
            (bool): If the repair was successful for not
        """
        partitions = self._get_partitions_from_keys(s3_buckets_and_keys)
        if not partitions:
            LOGGER.error('No partitons to add')
            return False

        for athena_table in partitions:
            partition_statement = ' '.join(
                ['PARTITION {0} LOCATION {1}'.format(partition, location)
                 for partition, location in partitions[athena_table].iteritems()])
            query = ('ALTER TABLE {athena_table} '
                     'ADD IF NOT EXISTS {partition_statement};'.format(
                         athena_table=athena_table,
                         partition_statement=partition_statement))

            success = self._athena_client.run_query(query=query)
            if not success:
                raise AthenaRefreshError(
                    'The add hive partition query has failed:\n{}'.format(query)
                )

            LOGGER.info('Successfully added the following partitions:\n%s',
                        json.dumps({athena_table: partitions[athena_table]}, indent=4))
        return True

    def run(self):
        """Poll the SQS queue for messages and create partitions for new data"""
        # Check that the database being used exists before running queries
        if not self._athena_client.check_database_exists():
            raise AthenaRefreshError(
                'The \'{}\' database does not exist'.format(self._athena_client.database)
            )

        # Get the first batch of messages from SQS.  If there are no
        # messages, this will exit early.
        self._sqs_client.get_messages(max_tries=2)

        if not self._sqs_client.received_messages:
            LOGGER.info('No SQS messages recieved, exiting')
            return

        # If the max amount of messages was initially returned,
        # then get the next batch of messages.  The max is determined based
        # on (number of tries) * (number of possible max messages returned)
        if len(self._sqs_client.received_messages) == 20:
            self._sqs_client.get_messages(max_tries=8)

        s3_buckets_and_keys = self._sqs_client.unique_s3_buckets_and_keys()
        if not s3_buckets_and_keys:
            LOGGER.error('No new Athena partitions to add, exiting')
            return

        if not self._add_partition(s3_buckets_and_keys):
            LOGGER.error('Failed to add hive partition(s)')
            return

        self._sqs_client.delete_messages()
        LOGGER.info('Deleted %d messages from SQS', self._sqs_client.deleted_message_count)


def handler(*_):
    """Athena Partition Refresher Handler Function"""
    AthenaRefresher().run()

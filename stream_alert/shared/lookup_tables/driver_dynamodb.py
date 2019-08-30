import json
import logging

import boto3
from botocore.exceptions import ClientError, ConnectTimeoutError, ReadTimeoutError

import stream_alert.shared.helpers.boto as boto_helpers
from stream_alert.shared.logger import get_logger
from stream_alert.shared.lookup_tables.cache import DriverCache
from stream_alert.shared.lookup_tables.drivers import PersistenceDriver
from stream_alert.shared.lookup_tables.errors import LookupTablesInitializationError

LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)


class DynamoDBDriver(PersistenceDriver):
    """
    DynamoDBDriver

    This driver is backed by DynamoDB, using it primarily as a key-value store. It is customizable,
    allowing the configuration to specify which column(s) that the partition/sort keys are named,
    as well as the "value" column.

    (!) NOTE: Currently, both the partition key and the sort key *MUST* be string types. It is
        not possible to have a non-string type for either of these.
    """
    def __init__(self, configuration):
        # Example configuration:
        # {
        #     "driver": "dynamodb",
        #     "table": "some_table_name",
        #     "partition_key": "MyPartitionKey",
        #     "sort_key": "MySortKey",
        #     "value_key": "MyValueKey",
        #     "cache_refresh_minutes": 2,
        #     "cache_maximum_key_count": 10,
        #     "consistent_read": false,
        #     "key_delimiter": ":"
        # }

        super(DynamoDBDriver, self).__init__(configuration)

        self._dynamo_db_table = configuration['table']
        self._dynamo_db_partition_key = configuration['partition_key']
        self._dynamo_db_value_key = configuration['value_key']
        self._dynamo_db_sort_key = configuration.get('sort_key', False)
        self._dynamo_consistent_read = configuration.get('consistent_read', True)

        self._cache = DriverCache(maximum_key_count=configuration.get('cache_maximum_key_count', 0))

        self._cache_refresh_minutes = configuration.get('cache_refresh_minutes', 3)

        self._key_delimiter = configuration.get('key_delimiter', ':')

        self._table = None

    @property
    def driver_type(self):
        return self.TYPE_DYNAMODB

    @property
    def id(self):
        return '{}:{}'.format(self.driver_type, self._dynamo_db_table)

    def initialize(self):
        # Setup DynamoDb client
        LOGGER.info('LookupTable (%s): Running initialization routine', self.id)

        try:
            boto_config = boto_helpers.default_config(timeout=10)
            resource = boto3.resource('dynamodb', config=boto_config)
            self._table = resource.Table(self._dynamo_db_table)
            _ = self._table.table_arn  # This is only here to blow up on invalid tables
        except ClientError as err:
            message = (
                'LookupTable ({}): Encountered error while connecting with DynamoDB: \'{}\''
            ).format(self.id, err.response['Error']['Message'])
            raise LookupTablesInitializationError(message)

    def commit(self):
        # FIXME (derek.wang)
        pass

    def get(self, key, default=None):
        self._reload_if_necessary(key)

        return self._cache.get(key, default)

    def set(self, key, value):
        # FIXME (derek.wang)
        pass

    def _reload_if_necessary(self, key):
        """
        Uses the "cache_refresh_minutes" option to determine whether or not the current LookupTable
        should be re-fetched from DynamoDb.

        If it needs a reload, this method will appropriately call reload.
        """
        if self._cache.has(key):
            LOGGER.debug(
                'LookupTable (%s): Key %s does not need refresh. TTL: %s',
                self.id,
                key,
                self._cache.ttl(key)
            )
        else:
            LOGGER.info(
                'LookupTable (%s): Key %s needs refresh, starting now.',
                self.id,
                key
            )
            self._load(key)

    def _load(self, key):
        # FIXME (derek.wang)
        #   Because of the way we explode the key using a delim, there is no way to do last-minute
        #   casting of sort key into a format OTHER than string. A sort key of 'N' (number) type
        #   simply will never work...
        if self._dynamo_db_sort_key:
            components = key.split(self._key_delimiter, 2)
            if len(components) != 2:
                LOGGER.error(
                    'LookupTable (%s): Invalid key. The requested table requires a sort key, '
                    'which the provided key \'%s\' does not provide, given the configured '
                    'delimiter: (%s)',
                    self.id,
                    key,
                    self._key_delimiter
                )
                return

            key_schema = {
                self._dynamo_db_partition_key: components[0],
                self._dynamo_db_sort_key: components[1],
            }
        else:
            key_schema = {
                self._dynamo_db_partition_key: key,
            }

        if LOGGER_DEBUG_ENABLED:
            # Guard json.dumps calls due to its expensive computation
            LOGGER.debug(
                'LookupTable (%s): Loading key \'%s\' with schema (%s)',
                self.id,
                key,
                json.dumps(key_schema)
            )

        try:
            get_item_args = {
                'Key': key_schema,
                # It's not urgently vital to do consistent reads; we accept that for some time we
                # may get out-of-date reads.
                'ConsistentRead': False,

                # FIXME (derek.wang) This should have a ProjectionExpression to prevent the
                #  response from returning irrelevant fields.
            }

            if LOGGER_DEBUG_ENABLED:
                get_item_args['ReturnConsumedCapacity'] = 'TOTAL'

            response = self._table.get_item(**get_item_args)

            # FIXME (derek.wang)
            #  on debug mode, log the capacity consumption

        except (ConnectTimeoutError, ReadTimeoutError):
            # Catching timeouts
            LOGGER.error(
                'LookupTable (%s): Reading from DynamoDB timed out',
                self.id
            )
            raise LookupTablesInitializationError(
                'LookupTable ({}): Reading from DynamoDB timed out'.format(self.id)
            )

        if 'Item' not in response:
            self._cache.set_blank(key, self._cache_refresh_minutes)
            return

        if self._dynamo_db_value_key not in response['Item']:
            self._cache.set_blank(key, self._cache_refresh_minutes)
            LOGGER.error(
                'LookupTable (%s): Requested value key %s seems to be missing from the table.',
                self.id,
                self._dynamo_db_value_key
            )
            return

        self._cache.set(
            key,
            response['Item'][self._dynamo_db_value_key],
            self._cache_refresh_minutes
        )
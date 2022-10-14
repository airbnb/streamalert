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
import logging

import boto3
from botocore.exceptions import (ClientError, ConnectTimeoutError,
                                 ReadTimeoutError)

import streamalert.shared.helpers.boto as boto_helpers
from streamalert.shared.logger import get_logger
from streamalert.shared.lookup_tables.cache import DriverCache
from streamalert.shared.lookup_tables.drivers import PersistenceDriver
from streamalert.shared.lookup_tables.errors import \
    LookupTablesInitializationError

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

        super().__init__(configuration)

        self._dynamo_db_table = configuration['table']
        self._dynamo_db_partition_key = configuration['partition_key']
        self._dynamo_db_value_key = configuration['value_key']
        self._dynamo_db_sort_key = configuration.get('sort_key', False)
        self._dynamo_consistent_read = configuration.get('consistent_read', True)

        self._cache = DriverCache(maximum_key_count=configuration.get('cache_maximum_key_count', 0))

        self._cache_refresh_minutes = configuration.get('cache_refresh_minutes', 3)

        self._key_delimiter = configuration.get('key_delimiter', ':')

        self._table = None

        self._dirty_rows = {}

    @property
    def driver_type(self):
        return self.TYPE_DYNAMODB

    @property
    def id(self):
        return f'{self.driver_type}:{self._dynamo_db_table}'

    def initialize(self):
        # Setup DynamoDB client
        LOGGER.info('LookupTable (%s): Running initialization routine', self.id)

        try:
            boto_config = boto_helpers.default_config(timeout=10)
            resource = boto3.resource('dynamodb', config=boto_config)
            self._table = resource.Table(self._dynamo_db_table)
            _ = self._table.table_arn  # This is only here to blow up on invalid tables
        except ClientError as err:
            message = f"LookupTable ({self.id}): Encountered error while connecting with DynamoDB: \'{err.response['Error']['Message']}\'"

            raise LookupTablesInitializationError(message) from err

    def commit(self):
        for key, value in self._dirty_rows.items():
            key_schema = self._convert_key_to_key_schema(key)

            if LOGGER_DEBUG_ENABLED:
                # Guard json.dumps calls due to its expensive computation
                LOGGER.debug('LookupTable (%s): Updating key \'%s\' with schema (%s)', self.id, key,
                             json.dumps(key_schema))

            try:
                item = key_schema
                item[self._dynamo_db_value_key] = value

                put_item_args = {
                    'Item': item,
                }

                if LOGGER_DEBUG_ENABLED:
                    put_item_args['ReturnConsumedCapacity'] = 'TOTAL'

                # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services
                #       /dynamodb.html#DynamoDB.Table.put_item
                self._table.put_item(**put_item_args)
                self._cache.set(key, value, self._cache_refresh_minutes)

            except (ClientError, ConnectTimeoutError, ReadTimeoutError) as e:
                raise LookupTablesInitializationError(f'LookupTable ({self.id}): Failure to set key') from e


        self._dirty_rows = {}

    def get(self, key, default=None):
        self._reload_if_necessary(key)

        return self._cache.get(key, default)

    def set(self, key, value):
        self._dirty_rows[key] = value

    def _reload_if_necessary(self, key):
        """
        Uses the "cache_refresh_minutes" option to determine whether or not the current LookupTable
        should be re-fetched from DynamoDB.

        If it needs a reload, this method will appropriately call reload.
        """
        if self._cache.has(key):
            LOGGER.debug('LookupTable (%s): Key %s does not need refresh. TTL: %s', self.id, key,
                         self._cache.ttl(key))
        else:
            LOGGER.info('LookupTable (%s): Key %s needs refresh, starting now.', self.id, key)
            self._load(key)

    def _load(self, key):
        key_schema = self._convert_key_to_key_schema(key)

        if LOGGER_DEBUG_ENABLED:
            # Guard json.dumps calls due to its expensive computation
            LOGGER.debug('LookupTable (%s): Loading key \'%s\' with schema (%s)', self.id, key,
                         json.dumps(key_schema))

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

            # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services
            #       /dynamodb.html#DynamoDB.Table.get_item
            response = self._table.get_item(**get_item_args)

        except (ConnectTimeoutError, ReadTimeoutError) as e:
            # Catching timeouts
            LOGGER.error('LookupTable (%s): Reading from DynamoDB timed out', self.id)
            raise LookupTablesInitializationError(f'LookupTable ({self.id}): Reading from DynamoDB timed out') from e


        if 'Item' not in response:
            self._cache.set_blank(key, self._cache_refresh_minutes)
            return

        if self._dynamo_db_value_key not in response['Item']:
            self._cache.set_blank(key, self._cache_refresh_minutes)
            LOGGER.error(
                'LookupTable (%s): Requested value key %s seems to be missing from the table.',
                self.id, self._dynamo_db_value_key)
            return

        self._cache.set(key, response['Item'][self._dynamo_db_value_key],
                        self._cache_refresh_minutes)

    def _convert_key_to_key_schema(self, key):
        """
        For DynamoDB, a key can either be a single string or can be a composition of TWO keys--the
        primary key + the sort key--that are delimited by a given delimiter.

        This function converts a given single string into a dict of pkey + sort key components.
        """
        # FIXME (derek.wang)
        #   Because of the way we explode the key using a delim, there is no way to do last-minute
        #   casting of sort key into a format OTHER than string. A sort key of 'N' (number) type
        #   simply will never work...
        if self._dynamo_db_sort_key:
            components = key.split(self._key_delimiter, 2)
            if len(components) != 2:
                message = (
                    f"LookupTable ({self.id}): Invalid key. The requested table requires a sort key, which the provided key ('{key}') "
                    f"does not provide, given the configured delimiter: '{self._key_delimiter}'")
                raise LookupTablesInitializationError(message)

            return {
                self._dynamo_db_partition_key: components[0],
                self._dynamo_db_sort_key: components[1],
            }

        return {
            self._dynamo_db_partition_key: key,
        }

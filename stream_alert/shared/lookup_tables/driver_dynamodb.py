from datetime import datetime, timedelta
import json
import time
import os
import sys
import zlib

import boto3
from botocore.exceptions import ClientError, ConnectTimeoutError, ReadTimeoutError

import stream_alert.shared.helpers.boto as boto_helpers
from stream_alert.shared.logger import get_logger
from stream_alert.shared.lookup_tables.drivers import PersistenceDriver
from stream_alert.shared.lookup_tables.errors import LookupTablesInitializationError

LOGGER = get_logger(__name__)


class DynamoDBDriver(PersistenceDriver):
    def __init__(self, configuration):
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
        self._dynamo_db_sort_key = configuration['sort_key']
        self._dynamo_db_value_key = configuration['value_key']
        self._dynamo_consistent_read = configuration['consistent_read']

        self._cache_maximum_key_count = configuration['cache_maximum_key_count']
        self._cache_refresh_minutes = configuration['cache_refresh_minutes']

        # FIXME we should not get this.... from env
        region = env.get('AWS_REGION') or env.get('AWS_DEFAULT_REGION') or 'us-east-1'
        self._client = boto3.client('dynamodb', region_name=region)

    @property
    def driver_type(self):
        return self.TYPE_DYNAMODB

    @property
    def id(self):
        return '{}:{}'.format(self.id, self._dynamo_db_table)

    def initialize(self):
        pass

    def commit(self):
        pass

    def get(self, key, default=None):
        response = self._client.get_item(
            TableName=self._dynamo_db_table,
            Key={
                'Key': {  # 'Key' is the name of partition key
                    'S': key,
                },
                # 'SortKey': FIXME (derek.wang)
            },

            # It's not urgently vital to do consistent reads; we accept that for some time we
            # may get out-of-date reads.
            ConsistentRead=False,
            ReturnConsumedCapacity='TOTAL',  # FIXME (derek.wang) Should be off for non-debug mode
            ProjectionExpression='Key,Value',
            ExpressionAttributeNames={
                'string': 'string'
            }
        )
        pass

    def set(self, key, value):
        pass

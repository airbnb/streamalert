from abc import abstractmethod, ABCMeta
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
from stream_alert.shared.lookup_tables.errors import LookupTablesInitializationError, \
    LookupTablesConfigurationError

LOGGER = get_logger(__name__)


class PersistenceDriver(object):

    TYPE_S3 = 's3'
    TYPE_DYNAMODB = 'dynamodb'
    TYPE_NULL = 'null'
    TYPE_EPHEMERAL = 'ephemeral'

    __metaclass__ = ABCMeta

    def __init__(self, configuration):
        self._configuration = configuration

    @property
    @abstractmethod
    def driver_type(self):
        """Returns a string that describes the type of driver"""

    @property
    @abstractmethod
    def id(self):
        """Returns a unique id for this driver"""

    @abstractmethod
    def initialize(self):
        """Configures and initializes this driver"""

    @abstractmethod
    def commit(self):
        """Takes any changes and flushes them"""

    @abstractmethod
    def get(self, key, default=None):
        """Retrieves a key"""

    @abstractmethod
    def set(self, key, value):
        """Sets the value of a key"""


def construct_persistence_driver(table_configuration):
    """
    Constructs a raw, uninitialized PersistenceDriver from the given configuration.

    :args
        table_configuration (dict)

    :return
        PersistenceDriver
    """
    driver_name = table_configuration.get('driver', False)

    if driver_name == PersistenceDriver.TYPE_S3:
        return S3Driver(table_configuration)
    elif driver_name == PersistenceDriver.TYPE_DYNAMODB:
        return DynamoDBDriver(table_configuration)
    elif driver_name == PersistenceDriver.TYPE_NULL:
        return NullDriver(table_configuration)
    elif driver_name == PersistenceDriver.TYPE_EPHEMERAL:
        return EphemeralDriver(table_configuration)
    else:
        raise LookupTablesConfigurationError(
            'Unrecognized driver name: {}'.format(driver_name)
        )


class EphemeralDriver(PersistenceDriver):
    """
    Ephemeral persistence driver

    This persistence driver does not actually store data anywhere--it just keeps it in memory.
    """

    def __init__(self, configuration):
        super(EphemeralDriver, self).__init__(configuration)
        self._cache = {}

    def initialize(self):
        pass

    def commit(self):
        pass

    @property
    def driver_type(self):
        return self.TYPE_EPHEMERAL

    @property
    def id(self):
        return '{}:{}'.format(self.driver_type, 1)

    def get(self, key, default=None):
        return self._cache.get(key, default)

    def set(self, key, value):
        self._cache[key] = value


class NullDriver(PersistenceDriver):
    """
    This driver does nothing... goes nowhere. It's simply to prevent our system from crashing
    if a nonexistent LookupTable is referenced--in this case, we simply return the Null table,
    backed by this NullDriver.
    """

    def __init__(self, configuration):
        super(NullDriver, self).__init__(configuration)

    @property
    def driver_type(self):
        return self.TYPE_NULL

    @property
    def id(self):
        return 'Null:Driver'

    def initialize(self):
        pass

    def commit(self):
        pass

    def get(self, _, default=None):
        return default

    def set(self, _, __):
        pass


class S3Driver(PersistenceDriver):

    def __init__(self, configuration):
        super(S3Driver, self).__init__(configuration)

        self._s3_bucket = 'airbnb.sample.lookuptable'
        self._s3_key = 'resource_map_current.gz'
        self._compression = 'gz'
        self._cache_refresh_minutes = 10
        self._load_time = 0

        self._s3_data = {}
        self._dirty = False

        # Explicitly set timeout for S3 connection. The boto default timeout is 60 seconds.
        boto_config = boto_helpers.default_config(timeout=10)
        self._s3_client = boto3.resource('s3', config=boto_config)

    @property
    def driver_type(self):
        return self.TYPE_S3

    @property
    def id(self):
        return '{}:{}/{}'.format(self.driver_type, self._s3_bucket, self._s3_key)

    def initialize(self):
        try:
            start_time = time.time()
            s3_object = self._s3_client.Object(self._s3_bucket, self._s3_key).get()
            size_kb = round(s3_object.get('ContentLength') / 1024.0, 2)
            size_mb = round(size_kb / 1024.0, 2)
            LOGGER.info(
                'LookupTable (%s): Downloaded S3 file size: %s',
                self.id,
                '{}MB'.format(size_mb) if size_mb else '{}KB'.format(size_kb)
            )

            data = s3_object.get('Body').read()
        except ClientError as err:
            LOGGER.error(
                'LookupTable (%s): Encountered error while downloading %s from %s: %s',
                self.id,
                self._s3_key,
                self._s3_bucket,
                err.response['Error']['Message']
            )
            raise LookupTablesInitializationError()

        except (ConnectTimeoutError, ReadTimeoutError):
            # Catching ConnectTimeoutError and ReadTimeoutError from botocore
            LOGGER.exception(
                'LookupTable (%s): Reading %s from S3 timed out',
                self.id,
                self._s3_key
            )
            # raise LookupTablesInitializationError()

        # The lookup data can optionally be compressed, so try to decompress
        # This will fall back and use the original data if decompression fails
        try:
            data = zlib.decompress(data, 47)
            LOGGER.info(
                'LookupTable (%s): Object decompressed to %d byte payload',
                self.id,
                sys.getsizeof(data)
            )
        except zlib.error:
            LOGGER.debug(
                'LookupTable (%s): Data in \'%s\' is not compressed',
                self.id,
                self._s3_key
            )

        try:
            self._s3_data = json.loads(data)
        except ValueError:
            LOGGER.exception(
                'LookupTable (%s): Failed to json decode data', self.id
            )

        total_time = time.time() - start_time
        LOGGER.info(
            'LookupTable (%s): Downloaded S3 file %s seconds', self.id, round(total_time, 2)
        )

    def commit(self):
        if not self._dirty:
            return

        raise NotImplementedError('Help derek you screwed me')

    def get(self, key, default=None):
        return self._s3_data.get(key, default)

    def set(self, key, value):
        self._s3_data.set(key, value)
        self._dirty = True

    def legacy_get_s3_internal_dict(self):
        """
        This method is hacked in simply to support reverse compatibility kind of cases.

        (!) DO NOT USE THIS METHOD UNLESS YOU KNOW WHAT YOU ARE DOING.
        (!) AVOID COPYING OR ALLOCATING SPACE AS THIS VARIABLE IS KNOWN TO BE LARGE AND CAN EAT
            UP LOTS OF MEMORY
        """
        return self._s3_data


class DynamoDBDriver(PersistenceDriver):
    def __init__(self, configuration):
        super(DynamoDBDriver, self).__init__(configuration)
        self._dynamo_db_table = 'table_name'

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

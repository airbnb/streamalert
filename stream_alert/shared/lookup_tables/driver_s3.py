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


class S3Driver(PersistenceDriver):
    """
    S3Driver

    This PersistenceDriver uses AWS S3 as the backing layer. The entire table is stored in a single
    large S3 file.

    Upon initialization, the S3 file is loaded, decompressed, decoded, and loaded into memory as
    a Python dict.

    The S3 file is reloaded every cache_refresh
    """

    def __init__(self, configuration):
        # {
        #     "driver": "s3",
        #     "bucket": "airbnb.sample.lookuptable",
        #     "key": "resource_map.gz",
        #     "cache_refresh_minutes": 10,
        #     "compression": "gzip",
        #     "key_delimiter": "|"
        # },

        super(S3Driver, self).__init__(configuration)

        self._s3_bucket = configuration['bucket']
        self._s3_key = configuration['key']
        self._compression = configuration.get('compression', False)
        self._cache_refresh_minutes = configuration['cache_refresh_minutes']
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
            raise LookupTablesInitializationError('LookupTable S3 Driver Failed')

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

        self._load_time = time.time()
        total_time = self._load_time - start_time
        LOGGER.info(
            'LookupTable (%s): Downloaded S3 file in %s seconds', self.id, round(total_time, 2)
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

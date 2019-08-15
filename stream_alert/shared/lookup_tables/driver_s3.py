from datetime import datetime, timedelta
import json
import time
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

    To improve performance, the decoded contents of the S3 file are cached in-memory for up to
    "cache_refresh_minutes" in minutes of time, after which they are reloaded from S3.

    (!) NOTE: Tweaking the cache_refresh_minutes will likely not help memory performance of your
        LookupTable. If you are having memory issues on your Lambda, try using the DynamoDBDriver.
    """
    _DEFAULT_CACHE_REFRESH_MINUTES = 10

    def __init__(self, configuration):
        # Example configuration:
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
        self._cache_refresh_minutes = configuration.get(
            'cache_refresh_minutes',
            self._DEFAULT_CACHE_REFRESH_MINUTES
        )

        self._last_load_time = None

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
        LOGGER.info('LookupTable (%s): Running initialization routine', self.id)
        self._reload()

    def commit(self):
        if not self._dirty:
            LOGGER.warn('LookupTable (%s): Empty commit; no records dirtied', self.id)
            return

        raise NotImplementedError('Help derek you screwed me')

    def get(self, key, default=None):
        self._reload_if_necessary()

        return self._s3_data.get(key, default)

    def set(self, key, value):
        self._s3_data.set(key, value)
        self._dirty = True

    def _reload_if_necessary(self):
        """
        Uses the "cache_refresh_minutes" option to determine whether or not the current LookupTable
        should be re-fetched from S3.

        If it needs a reload, this method will appropriately call reload.
        """
        now = datetime.utcnow()
        refresh_delta = timedelta(minutes=self._cache_refresh_minutes)
        needs_refresh = self._last_load_time + refresh_delta < now

        if not needs_refresh:
            LOGGER.debug(
                'LookupTable (%s): Does not need refresh. Last refresh: %s; Currently: %s',
                self.id,
                self._last_load_time,
                now
            )
            return

        LOGGER.info(
            'LookupTable (%s): Needs refresh, starting now. Last refresh: %s; Currently: %s',
            self.id,
            self._last_load_time,
            now
        )
        self._reload()

    def _reload(self):
        """
        Reaches to AWS S3, downloads the relevant data file, decompresses, decodes, and caches
        the file's contents into memory.
        """
        # First, download the item from S3
        try:
            start_time = time.time()
            s3_object = self._s3_client.Object(self._s3_bucket, self._s3_key).get()
            data = s3_object.get('Body').read()

            total_time = time.time() - start_time
            size_kb = round(s3_object.get('ContentLength') / 1024.0, 2)
            size_mb = round(size_kb / 1024.0, 2)
            LOGGER.debug(
                'LookupTable (%s): Downloaded S3 file size %s in %s seconds',
                self.id,
                '{}MB'.format(size_mb) if size_mb else '{}KB'.format(size_kb),
                round(total_time, 2)
            )
        except ClientError as err:
            LOGGER.error(
                'LookupTable (%s): Encountered error while downloading %s from %s: %s',
                self.id,
                self._s3_key,
                self._s3_bucket,
                err.response['Error']['Message']
            )
            raise LookupTablesInitializationError(
                'LookupTable S3 Driver Failed with Message: {}'.format(
                    err.response['Error']['Message']
                )
            )

        except (ConnectTimeoutError, ReadTimeoutError):
            # Catching ConnectTimeoutError and ReadTimeoutError from botocore
            LOGGER.error(
                'LookupTable (%s): Reading from S3 timed out',
                self.id
            )
            raise LookupTablesInitializationError(
                'LookupTable ({}): Reading from S3 timed out'.format(self.id)
            )

        # The lookup data can optionally be compressed, so try to decompress
        # This will fall back and use the original data if decompression fails
        if self._compression:
            try:
                data = zlib.decompress(data, 47)
                LOGGER.debug(
                    'LookupTable (%s): Object decompressed to %d byte payload',
                    self.id,
                    sys.getsizeof(data)
                )
            except zlib.error:
                LOGGER.warn(
                    'LookupTable (%s): Data is not compressed; defaulting to original payload',
                    self.id
                )
        else:
            LOGGER.debug('LookupTable (%s): File does not need decompression')

        # Decode the data; right now we make the assumption that the data is always encoded
        # as JSON.
        try:
            self._s3_data = json.loads(data)
            self._last_load_time = datetime.utcnow()
            LOGGER.debug(
                'LookupTable (%s): File successfully JSON decoded. Discovered %s keys.',
                self.id,
                len(self._s3_data)
            )
        except ValueError:
            LOGGER.exception(
                'LookupTable (%s): Failed to json decode data', self.id
            )

        LOGGER.info('LookupTable (%s): Successfully loaded', self.id)

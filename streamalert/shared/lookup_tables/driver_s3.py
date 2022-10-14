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
import sys
import time
import zlib

import boto3
from botocore.exceptions import (ClientError, ConnectTimeoutError,
                                 ReadTimeoutError)

import streamalert.shared.helpers.boto as boto_helpers
from streamalert.shared.logger import get_logger
from streamalert.shared.lookup_tables.cache import DriverCache
from streamalert.shared.lookup_tables.drivers import PersistenceDriver
from streamalert.shared.lookup_tables.errors import (
    LookupTablesCommitError, LookupTablesInitializationError)

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
    _MAGIC_CACHE_TTL_KEY = '____LAST_LOAD_TIME____'

    def __init__(self, configuration):
        # Example configuration:
        # {
        #     "driver": "s3",
        #     "bucket": "airbnb.sample.lookuptable",
        #     "key": "resource_map.gz",
        #     "cache_refresh_minutes": 10,
        #     "compression": "gzip"
        # },

        super().__init__(configuration)

        self._s3_bucket = configuration['bucket']
        self._s3_key = configuration['key']
        self._compression = configuration.get('compression', False)
        self._cache_refresh_minutes = configuration.get('cache_refresh_minutes',
                                                        self._DEFAULT_CACHE_REFRESH_MINUTES)

        self._cache = DriverCache(maximum_key_count=0)

        # S3 cannot support a per-key TTL so I use a separate DriverCache that stores
        # the global cache invalidation timer.
        self._cache_clock = DriverCache()
        self._dirty = False

        # Explicitly set timeout for S3 connection. The boto default timeout is 60 seconds.
        boto_config = boto_helpers.default_config(timeout=10)

        self._s3_adapter = S3Adapter(self, boto3.resource('s3', config=boto_config),
                                     self._s3_bucket, self._s3_key)

    @property
    def driver_type(self):
        return self.TYPE_S3

    @property
    def id(self):
        return f'{self.driver_type}:{self._s3_bucket}/{self._s3_key}'

    def initialize(self):
        LOGGER.info('LookupTable (%s): Running initialization routine', self.id)
        self._reload()

    def commit(self):
        if not self._dirty:
            LOGGER.warning('LookupTable (%s): Empty commit; no records dirtied', self.id)
            return

        data = Encoding.json_encode(self, self._cache.getall())

        # Compression
        if self._compression:
            data = Compression.gz_compress(self, data)
        else:
            LOGGER.debug('LookupTable (%s): File does not need decompression')

        # Upload to S3
        self._s3_adapter.upload(data)

        # Invalidate the cache key by setting a "False" value into the magic key
        self._cache_clock.set(self._MAGIC_CACHE_TTL_KEY, False, 9999)
        self._dirty = False

        LOGGER.info('LookupTable (%s): Successfully uploaded new data', self.id)

    def get(self, key, default=None):
        self._reload_if_necessary()
        return self._cache.get(key, default)

    def set(self, key, value):
        self._reload_if_necessary()
        self._cache.set(key, value, 9999)  # We don't do per-key cache TTLs
        self._dirty = True

    def _reload_if_necessary(self):
        """
        Uses the "cache_refresh_minutes" option to determine whether or not the current LookupTable
        should be re-fetched from S3.

        If it needs a reload, this method will appropriately call reload.
        """
        if self._cache_clock.has(self._MAGIC_CACHE_TTL_KEY) and \
                self._cache_clock.get(self._MAGIC_CACHE_TTL_KEY, False):
            LOGGER.debug('LookupTable (%s): Does not need refresh. TTL: %s', self.id,
                         self._cache_clock.ttl(self._MAGIC_CACHE_TTL_KEY))

        else:
            LOGGER.info('LookupTable (%s): Needs refresh, starting now.', self.id)
            self._reload()

    def _reload(self):
        """
        Reaches to AWS S3, downloads the relevant data file, decompresses, decodes, and caches
        the file's contents into memory.
        """
        # First, download the item from S3
        bytes_data = self._s3_adapter.download()

        # The lookup data can optionally be compressed, so try to decompress
        # This will fall back and use the original data if decompression fails
        if self._compression:
            bytes_data = Compression.gz_decompress(self, bytes_data)
        else:
            LOGGER.debug('LookupTable (%s): File does not need decompression')

        # Decode the data; right now we make the assumption that the data is always encoded
        # as JSON.
        data = Encoding.json_decode(self, bytes_data)

        # We don't do per-key cache TTLs; instead, we use a single global cache TTL that's set
        # as a "True" value in the magic key
        self._cache.setall(data, 9999)
        self._cache_clock.set(self._MAGIC_CACHE_TTL_KEY, True, self._cache_refresh_minutes)
        LOGGER.info('LookupTable (%s): Successfully loaded', self.id)


class Compression:
    @staticmethod
    def gz_decompress(driver, data):
        """
        Params:
            driver (PersistenceDriver)
            data (Bytes): Compressed data

        Return: Bytes
        """
        try:
            data = zlib.decompress(data, 47)
            LOGGER.debug('LookupTable (%s): Object decompressed to %d byte payload', driver.id,
                         sys.getsizeof(data))
        except zlib.error:
            LOGGER.warning(
                'LookupTable (%s): Data is not compressed; defaulting to original payload',
                driver.id)
        return data

    @staticmethod
    def gz_compress(driver, data):
        """
        Params:
            driver (PersistenceDriver)
            data (Bytes): Uncompressed data

        Return: Bytes
        """
        try:
            original_size = sys.getsizeof(data)
            data = zlib.compress(data, level=zlib.Z_BEST_COMPRESSION)
            LOGGER.debug('LookupTable (%s): Successfully compressed input data from %d to %d bytes',
                         driver.id, original_size, sys.getsizeof(data))
            return data
        except zlib.error:
            LOGGER.exception('LookupTable (%s): Data compression error.', driver.id)


class Encoding:
    """
    Encapsulation of encoding algorithms for S3 data.

    Right now we only support JSON encoding. In the future, we could potentially support
    """
    @staticmethod
    def json_encode(driver, data):
        """
        Params:
            driver (PersistenceDriver)
            data (string|dict|list|mixed):

        Returns: bytes
        """
        try:
            return json.dumps(data).encode()
        except (ValueError, TypeError):
            LOGGER.exception('LookupTable (%s): Failed to json encode data', driver.id)

    @staticmethod
    def json_decode(driver, bytes_data):
        """
        Params:
            driver (PersistenceDriver)
            bytes_data (bytes)

        Returns: (string|dict|list|mixed)
        """
        try:
            data = json.loads(bytes_data)
            LOGGER.debug('LookupTable (%s): File successfully JSON decoded. Discovered %s keys.',
                         driver.id, len(data))
            return data
        except ValueError:
            LOGGER.exception('LookupTable (%s): Failed to json decode data', driver.id)


class S3Adapter:
    """Adapter class that manages uploading data to and downloading data from AWS S3"""
    def __init__(self, driver, boto_s3_client, s3_bucket, s3_key):
        self._driver = driver
        self._s3_client = boto_s3_client
        self._s3_bucket = s3_bucket
        self._s3_key = s3_key

    def upload(self, bytes_data):
        """
        Params:
            bytes_data (bytes)
        """
        try:
            self._s3_client.Bucket(self._s3_bucket).put_object(Key=self._s3_key, Body=bytes_data)
            LOGGER.debug('LookupTable (%s): Object successfully uploaded to S3', self._driver.id)
        except ClientError as err:
            LOGGER.error('LookupTable (%s): Failed to upload to S3. Error message: %s',
                         self._driver.id, err.response['Error']['Message'])
            raise LookupTablesCommitError(f"LookupTable S3 Driver Failed with Message: {err.response['Error']['Message']}") from err


        except (ConnectTimeoutError, ReadTimeoutError) as e:
            # Catching ConnectTimeoutError and ReadTimeoutError from botocore
            LOGGER.error('LookupTable (%s): Reading from S3 timed out', self._driver.id)
            raise LookupTablesCommitError(f'LookupTable ({self._driver.id}): Reading from S3 timed out') from e

    def download(self):
        """
        Return: bytes
        """
        try:
            start_time = time.time()
            s3_object = self._s3_client.Object(self._s3_bucket, self._s3_key).get()
            bytes_data = s3_object.get('Body').read()

            total_time = time.time() - start_time
            size_kb = round(s3_object.get('ContentLength') / 1024.0, 2)
            size_mb = round(size_kb / 1024.0, 2)
            LOGGER.debug('LookupTable (%s): Downloaded S3 file size %s in %s seconds',
                         self._driver.id, f'{size_mb}MB' if size_mb else f'{size_kb}KB',
                         round(total_time, 2))

            return bytes_data
        except ClientError as err:
            LOGGER.error('LookupTable (%s): Encountered error while downloading %s from %s: %s',
                         self._driver.id, self._s3_key, self._s3_bucket,
                         err.response['Error']['Message'])
            raise LookupTablesInitializationError(f"LookupTable S3 Driver Failed with Message: {err.response['Error']['Message']}") from err


        except (ConnectTimeoutError, ReadTimeoutError) as e:
            # Catching ConnectTimeoutError and ReadTimeoutError from botocore
            LOGGER.error('LookupTable (%s): Reading from S3 timed out', self._driver.id)
            raise LookupTablesInitializationError(f'LookupTable ({self._driver.id}): Reading from S3 timed out') from e

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
from datetime import datetime, timedelta
import json
import os
import time
import zlib

import boto3
from botocore import client
from botocore.exceptions import ClientError, ReadTimeoutError, ConnectTimeoutError

from stream_alert.shared.logger import get_logger


LOGGER = get_logger(__name__)


class LookupTables(object):
    """Lookup Tables to useful information which can be referenced from rules"""

    _LOOKUP_TABLES_LAST_REFRESH = datetime(year=1970, month=1, day=1)

    # Explicitly set timeout for S3 connection. The default timeout is 60 seconds.
    BOTO_TIMEOUT = 10

    def __init__(self, buckets_info):
        boto_config = client.Config(
            connect_timeout=self.BOTO_TIMEOUT,
            read_timeout=self.BOTO_TIMEOUT
        )
        self._s3_client = boto3.resource('s3', config=boto_config)
        self._buckets_info = buckets_info

    def download_s3_objects(self):
        """Download S3 files (json format) from S3 buckets into memory.

        Returns:
            dict: A dictionary contains information loaded from S3. The file name
                will be the key, and value is file content in json format.
        """

        _lookup_tables = {}

        for bucket, files in self._buckets_info.iteritems():
            for json_file in files:
                try:
                    start_time = time.time()
                    s3_object = self._s3_client.Object(bucket, json_file).get()
                    size_kb = round(s3_object.get('ContentLength') / 1024.0, 2)
                    size_mb = round(size_kb / 1024.0, 2)
                    display_size = '{}MB'.format(size_mb) if size_mb else '{}KB'.format(size_kb)
                    LOGGER.info('Downloaded S3 file size %s and updated lookup table %s',
                                display_size, json_file)

                    data = s3_object.get('Body').read()
                except ClientError as err:
                    LOGGER.error('Encounterred error while downloading %s from %s, %s',
                                 json_file, bucket, err.response['Error']['Message'])
                    return _lookup_tables
                except(ReadTimeoutError, ConnectTimeoutError):
                    LOGGER.error('Reading %s from S3 is timed out.', json_file)
                    return _lookup_tables

                 # The lookup data can optionally be compressed, so try to decompress
                 # This will fall back and use the original data if decompression fails
                try:
                    data = zlib.decompress(data, 47)
                except zlib.error:
                    LOGGER.debug('Data in \'%s\' is not compressed', json_file)

                table_name = os.path.splitext(json_file)[0]
                _lookup_tables[table_name] = json.loads(data)

                total_time = time.time() - start_time
                LOGGER.info('Downloaded S3 file %s seconds', round(total_time, 2))

        return _lookup_tables

    @classmethod
    def load_lookup_tables(cls, config):
        """Load arbitrary json files to memory from S3 buckets when lookup table enabled

        The lookup tables will also be refreshed based on "cache_refresh_minutes" setting
        in the config.

        Args:
            config (dict): Loaded configuration from 'conf/' directory

        Returns:
            Return False if lookup table enabled or missing config. Otherwise, it
                will return an instance of LookupTables class.
        """
        lookup_tables = config['global']['infrastructure'].get('lookup_tables')
        if not (lookup_tables and lookup_tables.get('enabled', False)):
            return False

        buckets_info = lookup_tables.get('buckets')
        if not buckets_info:
            LOGGER.error('Buckets not defined')
            return False

        lookup_refresh_interval = lookup_tables.get('cache_refresh_minutes', 10)
        now = datetime.utcnow()
        refresh_delta = timedelta(minutes=lookup_refresh_interval)
        needs_refresh = cls._LOOKUP_TABLES_LAST_REFRESH + refresh_delta < now
        if not needs_refresh:
            LOGGER.debug('lookup tables do not need refresh (last refresh time: %s; '
                         'current time: %s)', cls._LOOKUP_TABLES_LAST_REFRESH, now)
            return False

        LOGGER.info('Refreshing lookup tables (last refresh time: %s; current time: %s)',
                    cls._LOOKUP_TABLES_LAST_REFRESH, now)

        cls._LOOKUP_TABLES_LAST_REFRESH = now

        return cls(buckets_info)

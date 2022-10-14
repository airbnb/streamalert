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
import zlib
from datetime import datetime
from unittest.mock import ANY, MagicMock, patch

import botocore
import pytest
from botocore.exceptions import ReadTimeoutError
from moto import mock_s3

from streamalert.shared.config import load_config
from streamalert.shared.lookup_tables.driver_s3 import (Compression, S3Adapter,
                                                        S3Driver)
from streamalert.shared.lookup_tables.drivers_factory import \
    construct_persistence_driver
from streamalert.shared.lookup_tables.errors import (
    LookupTablesCommitError, LookupTablesInitializationError)
from tests.unit.helpers.aws_mocks import put_mock_s3_object


class TestS3Driver:
    """
    Tests the S3Driver

    This was largely ported over from test_lookup_tables.py from the old implementation.
    """
    # pylint: disable=protected-access,attribute-defined-outside-init,no-self-use

    def setup(self):
        """LookupTables - Setup S3 bucket mocking"""
        self.buckets_info = {'bucket_name': ['foo.json', 'bar.json']}
        self.config = load_config('tests/unit/conf')
        self.s3_mock = mock_s3()
        self.s3_mock.start()

        self._foo_driver = construct_persistence_driver(
            self.config['lookup_tables']['tables']['foo']
        )
        self._bar_driver = construct_persistence_driver(
            self.config['lookup_tables']['tables']['bar']
        )
        self._bad_driver = construct_persistence_driver(
            {
                'driver': 's3',
                'bucket': 'bucket_name',
                'key': 'invalid-key',
            }
        )

        self._put_mock_tables()

    def _put_mock_tables(self):
        put_mock_s3_object('bucket_name', 'foo.json', json.dumps({
            'key_1': 'foo_1',
            'key_2': 'foo_2',
        }))
        put_mock_s3_object(
            'bucket_name', 'bar.json',
            zlib.compress(json.dumps({
                'key_1': 'compressed_bar_1',
                'key_2': 'compressed_bar_2',
            }).encode())
        )

    def teardown(self):
        self.s3_mock.stop()

    @patch('logging.Logger.info')
    def test_initialize(self, mock_logger):
        """LookupTables - Drivers - S3 Driver - Init"""
        self._foo_driver.initialize()
        mock_logger.assert_any_call(
            'LookupTable (%s): Running initialization routine',
            's3:bucket_name/foo.json'
        )
        mock_logger.assert_any_call(
            'LookupTable (%s): Successfully loaded',
            's3:bucket_name/foo.json'
        )

    def test_get(self):
        """LookupTables - Drivers - S3 Driver - Get Key"""
        self._foo_driver.initialize()
        assert self._foo_driver.get('key_1') == 'foo_1'

    @patch('logging.Logger.debug')
    def test_get_decompressed(self, mock_logger):
        """LookupTables - Drivers - S3 Driver - Compressed Get - Get Key"""
        self._bar_driver.initialize()
        assert self._bar_driver.get('key_1') == 'compressed_bar_1'

        mock_logger.assert_any_call(
            'LookupTable (%s): Object decompressed to %d byte payload',
            's3:bucket_name/bar.json',
            ANY
        )

    @patch('logging.Logger.warning')
    def test_get_decompression_fallback(self, mock_logger):
        """LookupTables - Drivers - S3 Driver - Compressed Get - Compression Fallback"""
        put_mock_s3_object(
            'bucket_name', 'bar.json',
            json.dumps({
                'key_1': 'not_compressed_bar_1',
                'key_2': 'not_compressed_bar_2',
            })
        )
        self._bar_driver.initialize()
        assert self._bar_driver.get('key_1') == 'not_compressed_bar_1'

        mock_logger.assert_any_call(
            'LookupTable (%s): Data is not compressed; defaulting to original payload',
            's3:bucket_name/bar.json'
        )

    def test_non_existent_key(self):
        """LookupTables - Drivers - S3 Driver - Get - Non-existent Key with default"""
        self._foo_driver.initialize()
        assert self._foo_driver.get('key_????', 'default?') == 'default?'

    @patch('logging.Logger.error')
    def test_non_existent_bucket_key(self, mock_logger):
        """LookupTables - Drivers - S3 Driver - Get - Non-existent Bucket Key"""
        pytest.raises(
            LookupTablesInitializationError,
            self._bad_driver.initialize
        )
        mock_logger.assert_any_call(
            'LookupTable (%s): Encountered error while downloading %s from %s: %s',
            's3:bucket_name/invalid-key',
            'invalid-key',
            'bucket_name',
            'The specified key does not exist.'
        )

    @patch('botocore.response.StreamingBody.read')
    @patch('logging.Logger.error')
    def test_botocore_read_timeout(self, mock_logger, mock_s3_conn):
        """LookupTables - Drivers - S3 Driver - Get - ReadTimeoutError"""
        mock_s3_conn.side_effect = ReadTimeoutError(
            'TestPool', 'Test Read timed out.', endpoint_url='test/url'
        )

        pytest.raises(
            LookupTablesInitializationError,
            self._foo_driver.initialize
        )

        mock_logger.assert_called_with(
            'LookupTable (%s): Reading from S3 timed out',
            's3:bucket_name/foo.json'
        )

    @patch('logging.Logger.debug')
    def test_no_need_refresh(self, mock_logger):
        """LookupTables - Drivers - S3 Driver - Refresh - Does not need refresh"""
        self._foo_driver.initialize()
        self._foo_driver.get('key_1')

        mock_logger.assert_any_call(
            'LookupTable (%s): Does not need refresh. TTL: %s',
            's3:bucket_name/foo.json',
            ANY
        )

    @patch('logging.Logger.debug')
    def test_barely_does_not_need_refresh(self, mock_logger):
        """LookupTables - Drivers - S3 Driver - Refresh - Barely Does not need refresh"""
        # Wind the clock back; note this is before initialize.
        self._foo_driver._cache_clock._clock.time_machine(datetime(year=3000, month=1, day=1))

        self._foo_driver.initialize()

        # Mess up some of the data so we fake that it's "stale"
        self._foo_driver._cache.set('key_1', 'stale', 10)  # 10-minute ttl

        # Wind the "clock" forward JUST BEFORE it needs a refresh
        self._foo_driver._cache_clock._clock.time_machine(
            datetime(year=3000, month=1, day=1, minute=9, second=59)
        )

        # Do another fetch and observe that it's still stale
        assert self._foo_driver.get('key_1') == 'stale'

        mock_logger.assert_any_call(
            'LookupTable (%s): Does not need refresh. TTL: %s',
            's3:bucket_name/foo.json', datetime(year=3000, month=1, day=1, minute=10)
        )

    @patch('logging.Logger.info')
    def test_needs_refresh(self, mock_logger):
        """LookupTables - Drivers - S3 Driver - Refresh - Needs refresh"""
        self._foo_driver.initialize()

        # Mess up some of the data so we fake that it's "stale"
        self._foo_driver._cache_clock._clock.time_machine(datetime(year=3000, month=1, day=1))
        self._foo_driver._cache.set('key_1', 'stale', 10)  # 10-minute ttl

        # Wind the "clock" forward JUST AFTER it needs a refresh
        self._foo_driver._cache_clock._clock.time_machine(
            datetime(year=3000, month=1, day=1, minute=10, second=1)
        )

        # Do another fetch and observe our updated results
        assert self._foo_driver.get('key_1') == 'foo_1'

        mock_logger.assert_any_call(
            'LookupTable (%s): Needs refresh, starting now.',
            's3:bucket_name/foo.json'
        )

    def test_set_commit_get(self):
        """LookupTables - Drivers - S3 Driver - Set Commit Get"""
        self._foo_driver.initialize()

        self._foo_driver.set('new_key', 'BazBuzz')
        self._foo_driver.commit()
        assert self._foo_driver.get('new_key') == 'BazBuzz'

    @patch('logging.Logger.warning')
    def test_set_commit_nothing(self, mock_logger):
        """LookupTables - Drivers - S3 Driver - Commit with nothing"""
        self._foo_driver.initialize()
        self._foo_driver.commit()
        mock_logger.assert_any_call(
            'LookupTable (%s): Empty commit; no records dirtied', 's3:bucket_name/foo.json'
        )


class TestCompression:

    @staticmethod
    def test_compression_decompression():
        """LookupTables - Drivers - S3 Driver - Compression"""
        original_data = 'Human is dead; Mismatch'
        driver = S3Driver({
            'bucket': 'bucket',
            'key': 'key',
            'compression': 'gzip'
        })

        compressed_data = Compression.gz_compress(driver, original_data.encode())
        decompressed_data = Compression.gz_decompress(driver, compressed_data)

        assert original_data == decompressed_data.decode()


class TestS3Adapter:

    @staticmethod
    def test_upload_with_error():
        """LookupTables - Drivers - S3 Driver - Adapter - AWS Error"""
        driver = S3Driver({
            'bucket': 'bucket',
            'key': 'key',
            'compression': 'gzip'
        })
        boto_s3_client = MagicMock(name='Boto3Client')
        boto_s3_client.Bucket.return_value.put_object.side_effect = \
            botocore.exceptions.ClientError({'Error': {'Message': 'uh oh'}}, 'operation_name')
        adapter = S3Adapter(
            driver,
            boto_s3_client,
            'bucket',
            'key'
        )

        pytest.raises(LookupTablesCommitError, adapter.upload, 'asdf')

    @staticmethod
    def test_upload_with_timeout():
        """LookupTables - Drivers - S3 Driver - Adapter - AWS Timeout"""
        driver = S3Driver({
            'bucket': 'bucket',
            'key': 'key',
            'compression': 'gzip'
        })
        boto_s3_client = MagicMock(name='Boto3Client')
        boto_s3_client.Bucket.return_value.put_object.side_effect = \
            botocore.exceptions.ConnectTimeoutError(endpoint_url='http://yay')
        adapter = S3Adapter(
            driver,
            boto_s3_client,
            'bucket',
            'key'
        )

        pytest.raises(LookupTablesCommitError, adapter.upload, 'asdf')

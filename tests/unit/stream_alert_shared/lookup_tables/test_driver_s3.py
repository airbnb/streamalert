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
import zlib

from botocore.exceptions import ReadTimeoutError
from mock import patch, ANY
from moto import mock_s3
from nose.tools import assert_equal, assert_raises

from stream_alert.shared.config import load_config
from stream_alert.shared.lookup_tables.drivers import construct_persistence_driver
from stream_alert.shared.lookup_tables.errors import LookupTablesInitializationError
from tests.unit.helpers.aws_mocks import put_mock_s3_object


class TestS3Driver(object):
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
            }))
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
        assert_equal(self._foo_driver.get('key_1'), 'foo_1')

    @patch('logging.Logger.debug')
    def test_get_decompressed(self, mock_logger):
        """LookupTables - Drivers - S3 Driver - Compressed Get - Get Key"""
        self._bar_driver.initialize()
        assert_equal(self._bar_driver.get('key_1'), 'compressed_bar_1')

        mock_logger.assert_any_call(
            'LookupTable (%s): Object decompressed to %d byte payload',
            's3:bucket_name/bar.json',
            95
        )

    @patch('logging.Logger.warn')
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
        assert_equal(self._bar_driver.get('key_1'), 'not_compressed_bar_1')

        mock_logger.assert_any_call(
            'LookupTable (%s): Data is not compressed; defaulting to original payload',
            's3:bucket_name/bar.json'
        )

    def test_non_existent_key(self):
        """LookupTables - Drivers - S3 Driver - Get - Non-existent Key with default"""
        self._foo_driver.initialize()
        assert_equal(self._foo_driver.get('key_????', 'default?'), 'default?')

    @patch('logging.Logger.error')
    def test_non_existent_bucket_key(self, mock_logger):
        """LookupTables - Drivers - S3 Driver - Get - Non-existent Bucket Key"""
        assert_raises(
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

        assert_raises(
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
            'LookupTable (%s): Does not need refresh. Last refresh: %s; Currently: %s',
            ANY, ANY, ANY
        )

    @patch('logging.Logger.debug')
    def test_barely_does_not_need_refresh(self, mock_logger):
        """LookupTables - Drivers - S3 Driver - Refresh - Barely Does not need refresh"""
        self._foo_driver.initialize()

        # Mess up some of the data so we fake that it's "stale"
        self._foo_driver._s3_data['key_1'] = 'stale'
        assert_equal(self._foo_driver.get('key_1'), 'stale')

        # Wind the "clock" back JUST before it needs a refresh
        self._foo_driver._last_load_time = datetime.utcnow() - timedelta(minutes=9, seconds=59)

        # Do another fetch and observe that it's still stale
        assert_equal(self._foo_driver.get('key_1'), 'stale')

        mock_logger.assert_any_call(
            'LookupTable (%s): Does not need refresh. Last refresh: %s; Currently: %s',
            ANY, ANY, ANY
        )

    @patch('logging.Logger.info')
    def test_needs_refresh(self, mock_logger):
        """LookupTables - Drivers - S3 Driver - Refresh - Needs refresh"""
        self._foo_driver.initialize()

        # Mess up some of the data so we fake that it's "stale"
        self._foo_driver._s3_data['key_1'] = 'wrong'
        assert_equal(self._foo_driver.get('key_1'), 'wrong')

        # Wind the "clock" way back
        self._foo_driver._last_load_time = datetime.utcnow() - timedelta(minutes=10, seconds=1)

        # Do another fetch and observe our updated results
        assert_equal(self._foo_driver.get('key_1'), 'foo_1')

        mock_logger.assert_any_call(
            'LookupTable (%s): Needs refresh, starting now. Last refresh: %s; Currently: %s',
            ANY, ANY, ANY
        )

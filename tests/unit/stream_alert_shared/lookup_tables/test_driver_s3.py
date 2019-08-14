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
from datetime import datetime
import json
import os
import zlib

from botocore.exceptions import ReadTimeoutError

from mock import patch
from moto import mock_s3
from nose.tools import assert_equal

from stream_alert.shared.config import load_config
from stream_alert.shared.lookup_tables.drivers import construct_persistence_driver
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
        """LookupTables - Drivers - S3 Driver - Get Key"""
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
        """LookupTables - Drivers - S3 Driver - Compressed Data - Get Key"""
        self._bar_driver.initialize()
        assert_equal(self._bar_driver.get('key_1'), 'compressed_bar_1')

        mock_logger.assert_any_call(
            'LookupTable (%s): Object decompressed to %d byte payload',
            's3:bucket_name/bar.json',
            95
        )

    # @patch('logging.Logger.error')
    # def test_download_s3_object_bucket_exception(self, mock_logger):
    #     """LookupTables - Download S3 Object, Bucket Does Not Exist"""
    #     LookupTables._download_s3_objects({'wrong_bucket': ['foo.json']})
    #     mock_logger.assert_called_with(
    #         'Encounterred error while downloading %s from %s, %s',
    #         'foo.json',
    #         'wrong_bucket',
    #         'The specified bucket does not exist'
    #     )
    #
    # @patch('botocore.response.StreamingBody.read')
    # @patch('logging.Logger.exception')
    # def test_download_s3_object_bucket_timeout(self, mock_logger, mock_s3_conn):
    #     """LookupTables - Download S3 Object, ReadTimeoutError"""
    #     mock_s3_conn.side_effect = ReadTimeoutError(
    #         'TestPool', 'Test Read timed out.', endpoint_url='test/url'
    #     )
    #     self.buckets_info['bucket_name'].pop()
    #     LookupTables._download_s3_objects(self.buckets_info)
    #     assert_equal(LookupTables._tables, {})
    #     mock_logger.assert_called_with('Reading %s from S3 timed out', 'foo.json')
    #
    # def test_load_lookup_tables_missing_config(self):
    #     """LookupTables - Load Lookup Tables, Missing Config"""
    #     # Remove lookup_tables config for this test case.
    #     self.config['global']['infrastructure'].pop('lookup_tables')
    #     lookup_tables = LookupTables.load_lookup_tables(self.config)
    #     assert_equal(lookup_tables, False)
    #     assert_equal(LookupTables._LOOKUP_TABLES_LAST_REFRESH,
    #                  datetime(year=1970, month=1, day=1))
    #
    # @patch('logging.Logger.error')
    # def test_load_lookup_tables_missing_buckets(self, log_mock):
    #     """LookupTables - Load Lookup Tables, Missing Buckets"""
    #     del self.config['global']['infrastructure']['lookup_tables']['buckets']
    #     self.config['global']['infrastructure']['lookup_tables']['enabled'] = True
    #     LookupTables.load_lookup_tables(self.config)
    #     log_mock.assert_called_with('Buckets not defined')
    #
    # def test_load_lookup_tables(self):
    #     """LookupTables - Load Lookup Table"""
    #     self.config['global']['infrastructure']['lookup_tables']['enabled'] = True
    #     with patch.object(LookupTables, '_download_s3_objects') as download_mock:
    #         result = LookupTables.load_lookup_tables(self.config)
    #
    #         download_mock.assert_called_with(self.buckets_info)
    #         assert_equal(result, LookupTables)
    #         assert_equal(
    #             LookupTables._LOOKUP_TABLES_LAST_REFRESH != datetime(year=1970, month=1, day=1),
    #             True
    #         )
    #
    # def test_load_lookup_tables_no_refresh(self):
    #     """LookupTables - Load Lookup Table, No Refresh"""
    #     self.config['global']['infrastructure']['lookup_tables']['enabled'] = True
    #     LookupTables._LOOKUP_TABLES_LAST_REFRESH = datetime.utcnow()
    #     with patch.object(LookupTables, '_download_s3_objects') as download_mock:
    #         result = LookupTables.load_lookup_tables(self.config)
    #         download_mock.assert_not_called()
    #         assert_equal(result, LookupTables)

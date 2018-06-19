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

from botocore.vendored.requests.packages.urllib3.exceptions import ReadTimeoutError

from mock import patch
from moto import mock_s3
from nose.tools import assert_equal

from stream_alert_cli.helpers import put_mock_s3_object
from stream_alert.shared.config import load_config
from stream_alert.shared.lookup_tables import LookupTables

# pylint: disable=protected-access
class TestLookupTables(object):
    """Test LookupTables class"""
    def __init__(self):
        self.buckets_info = {'bucket_name': ['foo.json', 'bar.json']}
        self.region = 'us-east-1'

    def setup(self):
        """LookupTables - Setup S3 bucket mocking"""
        # pylint: disable=attribute-defined-outside-init
        self.config = load_config('tests/unit/conf')
        self.lookup_tables = LookupTables(self.buckets_info)
        self.s3_mock = mock_s3()
        self.s3_mock.start()
        for bucket, files in self.buckets_info.iteritems():
            for json_file in files:
                put_mock_s3_object(
                    bucket,
                    json_file,
                    json.dumps({
                        '{}_key'.format(bucket): '{}_value'.format(os.path.splitext(json_file)[0])
                    }),
                    self.region
                )

    def teardown(self):
        """LookupTables - Stop S3 bucket mocking"""
        self.s3_mock.stop()
        LookupTables._LOOKUP_TABLES_LAST_REFRESH = datetime(year=1970, month=1, day=1)

    def test_download_s3_object(self):
        """LookupTables - Download s3 object"""
        result = self.lookup_tables.download_s3_objects()
        assert_equal(result.keys(), ['foo', 'bar'])
        expect_result = {
            'foo': {'bucket_name_key': 'foo_value'},
            'bar': {'bucket_name_key': 'bar_value'}
        }
        assert_equal(result, expect_result)

    @patch('logging.Logger.error')
    def test_download_s3_object_bucket_exception(self, mock_logger): # pylint: disable=no-self-use
        """LookupTables - S3 bucket doesn't exist"""
        lookup_tables = LookupTables({'wrong_bucket': ['foo.json']})
        lookup_tables.download_s3_objects()
        mock_logger.assert_called_with(
            'Encounterred error while downloading %s from %s, %s',
            'foo.json',
            'wrong_bucket',
            'The specified bucket does not exist'
        )

    @patch('botocore.response.StreamingBody.read')
    @patch('logging.Logger.error')
    def test_download_s3_object_bucket_timeout(self, mock_logger, mock_s3_conn): # pylint: disable=no-self-use
        """LookupTables - Read file from S3 timeout"""
        mock_s3_conn.side_effect = ReadTimeoutError(
            'TestPool', 'Test url', 'Test Read timed out.'
        )
        result = self.lookup_tables.download_s3_objects()
        assert_equal(result, {})
        mock_logger.assert_called_with(
            'Reading %s from S3 is timed out.', 'foo.json'
        )

    def test_download_s3_object_file_exception(self): # pylint: disable=no-self-use
        """LookupTables - S3 file doesn't exist"""
        lookup_tables = LookupTables({'bucket_name': ['wrong_file']})
        lookup_tables.download_s3_objects()

    @patch('logging.Logger.error')
    def test_load_lookup_tables_missing_config(self, mock_logger):
        """LookupTables - Load lookup tables with missing config"""
        # Remove lookup_tables config for this test case.
        self.config['global']['infrastructure'].pop('lookup_tables')
        lookup_tables = LookupTables.load_lookup_tables(self.config)
        assert_equal(lookup_tables, False)
        assert_equal(LookupTables._LOOKUP_TABLES_LAST_REFRESH,
                     datetime(year=1970, month=1, day=1))

        self.config['global']['infrastructure']['lookup_tables'] = {
            'cache_refresh_minutes': 10,
            'enabled': True
        }
        lookup_tables = LookupTables.load_lookup_tables(self.config)
        mock_logger.assert_called_with('Buckets not defined')

    @patch('logging.Logger.debug')
    def test_load_lookup_tables(self, mock_logger):
        """LookupTables - Load lookup table"""
        self.config['global']['infrastructure']['lookup_tables']['enabled'] = True
        lookup_tables = LookupTables.load_lookup_tables(self.config)
        result = lookup_tables.download_s3_objects()

        assert_equal(result.get('foo'), {'bucket_name_key': 'foo_value'})
        assert_equal(result.get('bar'), {'bucket_name_key': 'bar_value'})
        assert_equal(result.get('not_exist'), None)

        LookupTables.load_lookup_tables(self.config)
        mock_logger.assert_called()

    @patch('logging.Logger.debug')
    def test_load_lookup_tables_compresed(self, mock_logger):
        """LookupTables - Load lookup table, compressed file"""
        self.config['global']['infrastructure']['lookup_tables']['enabled'] = True
        lookup_tables = LookupTables.load_lookup_tables(self.config)
        # Replace one of the S3 objects with a compressed version
        put_mock_s3_object(
            'bucket_name',
            'bar.json',
            zlib.compress(json.dumps({'compressed_key': 'compressed_val'})),
            self.region
        )
        result = lookup_tables.download_s3_objects()

        assert_equal(result.get('bar'), {'compressed_key': 'compressed_val'})
        assert_equal(result.get('foo'), {'bucket_name_key': 'foo_value'})
        mock_logger.assert_any_call('Data in \'%s\' is not compressed', 'foo.json')

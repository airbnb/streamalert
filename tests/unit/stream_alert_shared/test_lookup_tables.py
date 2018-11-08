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

from stream_alert.shared.config import load_config
from stream_alert.shared.lookup_tables import LookupTables
from tests.unit.helpers.aws_mocks import put_mock_s3_object


class TestLookupTables(object):
    """Test LookupTables class"""
    # pylint: disable=protected-access,attribute-defined-outside-init,no-self-use

    def setup(self):
        """LookupTables - Setup S3 bucket mocking"""
        self.buckets_info = {'bucket_name': ['foo.json', 'bar.json']}
        self.config = load_config('tests/unit/conf')
        self.s3_mock = mock_s3()
        self.s3_mock.start()
        self._put_mock_tables()

    def _put_mock_tables(self):
        for bucket, files in self.buckets_info.iteritems():
            for json_file in files:
                put_mock_s3_object(
                    bucket,
                    json_file,
                    json.dumps({
                        '{}_key'.format(bucket): '{}_value'.format(os.path.splitext(json_file)[0])
                    })
                )

    def teardown(self):
        """LookupTables - Stop S3 bucket mocking"""
        self.s3_mock.stop()
        LookupTables._LOOKUP_TABLES_LAST_REFRESH = datetime(year=1970, month=1, day=1)
        LookupTables._tables = {}

    def test_download_s3_object(self):
        """LookupTables - Download S3 Object"""
        LookupTables._download_s3_objects(self.buckets_info)
        expected_result = {
            'foo': {'bucket_name_key': 'foo_value'},
            'bar': {'bucket_name_key': 'bar_value'}
        }
        assert_equal(LookupTables._tables, expected_result)

    @patch('logging.Logger.debug')
    def test_download_s3_object_compressed(self, mock_logger):
        """LookupTables - Download S3 Object, Compressed File"""
        put_mock_s3_object(
            'bucket_name',
            'bar.json',
            zlib.compress(json.dumps({'compressed_key': 'compressed_val'}))
        )

        expected_result = {
            'foo': {'bucket_name_key': 'foo_value'},
            'bar': {'compressed_key': 'compressed_val'}
        }

        LookupTables._download_s3_objects(self.buckets_info)

        assert_equal(LookupTables._tables, expected_result)
        mock_logger.assert_any_call('Data in \'%s\' is not compressed', 'foo.json')

    @patch('logging.Logger.error')
    def test_download_s3_object_bucket_exception(self, mock_logger):
        """LookupTables - Download S3 Object, Bucket Does Not Exist"""
        LookupTables._download_s3_objects({'wrong_bucket': ['foo.json']})
        mock_logger.assert_called_with(
            'Encounterred error while downloading %s from %s, %s',
            'foo.json',
            'wrong_bucket',
            'The specified bucket does not exist'
        )

    @patch('botocore.response.StreamingBody.read')
    @patch('logging.Logger.error')
    def test_download_s3_object_bucket_timeout(self, mock_logger, mock_s3_conn):
        """LookupTables - Download S3 Object, ReadTimeoutError"""
        mock_s3_conn.side_effect = ReadTimeoutError(
            'TestPool', 'Test url', 'Test Read timed out.'
        )
        self.buckets_info['bucket_name'].pop()
        LookupTables._download_s3_objects(self.buckets_info)
        assert_equal(LookupTables._tables, {})
        mock_logger.assert_called_with('Reading %s from S3 is timed out.', 'foo.json')

    def test_load_lookup_tables_missing_config(self):
        """LookupTables - Load Lookup Tables, Missing Config"""
        # Remove lookup_tables config for this test case.
        self.config['global']['infrastructure'].pop('lookup_tables')
        lookup_tables = LookupTables.load_lookup_tables(self.config)
        assert_equal(lookup_tables, False)
        assert_equal(LookupTables._LOOKUP_TABLES_LAST_REFRESH,
                     datetime(year=1970, month=1, day=1))

    @patch('logging.Logger.error')
    def test_load_lookup_tables_missing_buckets(self, log_mock):
        """LookupTables - Load Lookup Tables, Missing Buckets"""
        del self.config['global']['infrastructure']['lookup_tables']['buckets']
        self.config['global']['infrastructure']['lookup_tables']['enabled'] = True
        LookupTables.load_lookup_tables(self.config)
        log_mock.assert_called_with('Buckets not defined')

    def test_load_lookup_tables(self):
        """LookupTables - Load Lookup Table"""
        self.config['global']['infrastructure']['lookup_tables']['enabled'] = True
        with patch.object(LookupTables, '_download_s3_objects') as download_mock:
            result = LookupTables.load_lookup_tables(self.config)

            download_mock.assert_called_with(self.buckets_info)
            assert_equal(result, LookupTables)
            assert_equal(
                LookupTables._LOOKUP_TABLES_LAST_REFRESH != datetime(year=1970, month=1, day=1),
                True
            )

    def test_load_lookup_tables_no_refresh(self):
        """LookupTables - Load Lookup Table, No Refresh"""
        self.config['global']['infrastructure']['lookup_tables']['enabled'] = True
        LookupTables._LOOKUP_TABLES_LAST_REFRESH = datetime.utcnow()
        with patch.object(LookupTables, '_download_s3_objects') as download_mock:
            result = LookupTables.load_lookup_tables(self.config)
            download_mock.assert_not_called()
            assert_equal(result, LookupTables)

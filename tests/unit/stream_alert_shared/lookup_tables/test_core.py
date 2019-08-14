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
import json
import zlib

from moto import mock_s3
from nose.tools import assert_equal

from stream_alert.shared.config import load_config
from stream_alert.shared.lookup_tables.core import LookupTablesCore
from tests.unit.helpers.aws_mocks import put_mock_s3_object


class TestLookupTablesCore(object):
    """

    """
    # pylint: disable=protected-access,attribute-defined-outside-init,no-self-use
    def setup(self):
        """LookupTables - Setup S3 bucket mocking"""
        self.config = load_config('tests/unit/conf')

        self.s3_mock = mock_s3()
        self.s3_mock.start()

        self._put_mock_data()

        self._lookup_tables = LookupTablesCore.load_lookup_tables(self.config)

    def _put_mock_data(self):
        # S3 mock data
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

    def test_get(self):
        """LookupTables - Core - get()"""
        assert_equal(self._lookup_tables.get('foo', 'key_1'), 'foo_1')

    def test_get_table(self):
        """LookupTables - Core - table()"""
        table = self._lookup_tables.table('foo')
        assert_equal(table.get('key_2'), 'foo_2')

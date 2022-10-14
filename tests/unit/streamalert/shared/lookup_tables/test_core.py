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
from unittest.mock import ANY, patch

from moto import mock_dynamodb, mock_s3

from streamalert.shared.config import load_config
from streamalert.shared.lookup_tables.core import LookupTables
from tests.unit.helpers.aws_mocks import (put_mock_dynamod_data,
                                          put_mock_s3_object)


class TestLookupTablesCore:
    """
    Tests LookupTablesCore
    """
    # pylint: disable=protected-access,attribute-defined-outside-init,no-self-use

    def setup(self):
        """LookupTables - Setup S3 bucket mocking"""
        self.config = load_config('tests/unit/conf')

        self.s3_mock = mock_s3()
        self.s3_mock.start()

        self.dynamodb_mock = mock_dynamodb()
        self.dynamodb_mock.start()

        self._put_mock_data()

        self._lookup_tables = LookupTables.get_instance(
            config=self.config,
            reset=True
        )

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
            }).encode())
        )

        # DynamoDB Mock data
        # Build a new dynamodb schema matching the tables configured
        put_mock_dynamod_data(
            'table_name',
            {
                'AttributeDefinitions': [
                    {
                        'AttributeName': 'MyPartitionKey',
                        'AttributeType': 'S'
                    },
                    {
                        'AttributeName': 'MySortKey',
                        'AttributeType': 'S'
                    }
                ],
                'KeySchema': [
                    {
                        'AttributeName': 'MyPartitionKey',
                        'KeyType': 'HASH'
                    },
                    {
                        'AttributeName': 'MySortKey',
                        'KeyType': 'RANGE'
                    }
                ],
            },
            [
                {
                    'MyPartitionKey': 'aaaa',
                    'MySortKey': '1',
                    'MyValueKey': 'Over 9000!',
                }
            ]
        )

    def teardown(self):
        self.s3_mock.stop()
        self.dynamodb_mock.stop()

    def test_get(self):
        """LookupTables - Core - get()"""
        assert self._lookup_tables.get('foo', 'key_1') == 'foo_1'

    def test_get_table_s3(self):
        """LookupTables - Core - table() - S3"""
        table = self._lookup_tables.table('foo')
        assert table.get('key_2') == 'foo_2'

    def test_get_table_dynamodb(self):
        """LookupTables - Core - table() - DynamoDB"""
        table = self._lookup_tables.table('dinosaur')
        assert table.get('aaaa:1') == 'Over 9000!'

    @patch('logging.Logger.error')
    def test_get_nonexistent_table(self, mock_logger):
        """LookupTables - Core - table()"""
        table = self._lookup_tables.table('does-not-exist')
        assert table.get('key_2') is None

        mock_logger.assert_any_call(
            (
                'Nonexistent LookupTable \'%s\' referenced. Defaulting to null table. '
                'Valid tables were (%s)'
            ),
            'does-not-exist',
            ANY
        )

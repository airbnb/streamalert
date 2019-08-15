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

import boto3
from mock import ANY, patch
from moto import mock_s3, mock_dynamodb2
from nose.tools import assert_equal

from stream_alert.shared.config import load_config
from stream_alert.shared.lookup_tables.core import LookupTables
from tests.unit.helpers.aws_mocks import put_mock_s3_object


class TestLookupTablesCore(object):
    """
    Tests LookupTablesCore
    """
    # pylint: disable=protected-access,attribute-defined-outside-init,no-self-use
    def setup(self):
        """LookupTables - Setup S3 bucket mocking"""
        self.config = load_config('tests/unit/conf')

        self.s3_mock = mock_s3()
        self.s3_mock.start()

        self.dynamodb_mock = mock_dynamodb2()
        self.dynamodb_mock.start()

        self._put_mock_data()

        self._lookup_tables = LookupTables.get_instance(self.config)

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

        # DynamoDB Mock data
        # Build a new dynamodb schema matching the tables configured
        boto3.client('dynamodb').create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': 'MyPartitionKey',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'MySortKey',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'MyValueKey',
                    'AttributeType': 'S'
                }
            ],
            KeySchema=[
                {
                    'AttributeName': 'MyPartitionKey',
                    'KeyType': 'HASH'
                },
                {
                    'AttributeName': 'MySortKey',
                    'KeyType': 'RANGE'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            },
            TableName='table_name'
        )

        table = boto3.resource('dynamodb').Table('table_name')
        with table.batch_writer() as batch:
            batch.put_item(
                Item={
                    'MyPartitionKey': 'aaaa',
                    'MySortKey': '1',
                    'MyValueKey': 'Over 9000!',
                }
            )

    def teardown(self):
        self.s3_mock.stop()
        self.dynamodb_mock.stop()

    def test_get(self):
        """LookupTables - Core - get()"""
        assert_equal(self._lookup_tables.get('foo', 'key_1'), 'foo_1')

    def test_get_table_s3(self):
        """LookupTables - Core - table() - S3"""
        table = self._lookup_tables.table('foo')
        assert_equal(table.get('key_2'), 'foo_2')

    def test_get_table_dynamodb(self):
        """LookupTables - Core - table() - DynamoDB"""
        table = self._lookup_tables.table('dinosaur')
        assert_equal(table.get('aaaa:1'), 'Over 9000!')

    @patch('logging.Logger.error')
    def test_get_nonexistent_table(self, mock_logger):
        """LookupTables - Core - table()"""
        table = self._lookup_tables.table('does-not-exist')
        assert_equal(table.get('key_2'), None)

        mock_logger.assert_any_call(
            (
                'Nonexistent LookupTable \'%s\' referenced. Defaulting to null table. '
                'Valid tables were (%s)'
            ),
            'does-not-exist',
            ANY
        )

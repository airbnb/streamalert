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
import boto3
import json
import os
import zlib

from botocore.exceptions import ReadTimeoutError

from mock import patch, ANY
from moto import mock_dynamodb2
from nose.tools import assert_equal, assert_false, assert_raises, assert_true

from stream_alert.shared.config import load_config
from stream_alert.shared.lookup_tables.drivers import construct_persistence_driver
from stream_alert.shared.lookup_tables.errors import LookupTablesInitializationError
from tests.unit.helpers.aws_mocks import put_mock_s3_object


class TestDynamoDBDriver(object):
    """
    Tests the S3Driver

    This was largely ported over from test_lookup_tables.py from the old implementation.
    """
    # pylint: disable=protected-access,attribute-defined-outside-init,no-self-use
    def setup(self):
        """LookupTables - Setup S3 bucket mocking"""
        self.config = load_config('tests/unit/conf')
        self._dynamodb_mock = mock_dynamodb2()
        self._dynamodb_mock.start()

        self._driver = construct_persistence_driver(
            self.config['lookup_tables']['tables']['dinosaur']
        )
        self._bad_driver = construct_persistence_driver(
            {
                'driver': 'dynamodb',
                'table': 'table???',
                'partition_key': '??',
                'value_key': '?zlaerf',
            }
        )

        self._put_mock_tables()

    def _put_mock_tables(self):
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
                    'MyValueKey': 'could_this_be_a_foo?',
                }
            )
            batch.put_item(
                Item={
                    'MyPartitionKey': 'aaaa',
                    'MySortKey': '2',
                    'MyValueKey': 'or_is_this_just_fantasy?',
                }
            )
            batch.put_item(
                Item={
                    'MyPartitionKey': 'aaaa',
                    'MySortKey': '3',
                    'MyValueKey': 'no_couldnt_be',
                }
            )
            batch.put_item(
                Item={
                    'MyPartitionKey': 'bbbb',
                    'MySortKey': '1',
                    'MyValueKey': 'beeffedfeedbeefdeaddeafbeddab',
                }
            )

    def teardown(self):
        self._dynamodb_mock.stop()

    @patch('logging.Logger.info')
    def test_initialize(self, mock_logger):
        """LookupTables - Drivers - DynamoDb Driver - Init"""
        self._driver.initialize()
        mock_logger.assert_any_call(
            'LookupTable (%s): Running initialization routine',
            'dynamodb:table_name'
        )

    def test_get(self):
        """LookupTables - Drivers - DynamoDb Driver - Get Key"""
        self._driver.initialize()
        assert_equal(self._driver.get('aaaa:1'), 'could_this_be_a_foo?')

    def test_get_2(self):
        """LookupTables - Drivers - DynamoDb Driver - Get Key #2"""
        self._driver.initialize()
        assert_equal(self._driver.get('aaaa:2'), 'or_is_this_just_fantasy?')

    def test_non_existent_key(self):
        """LookupTables - Drivers - DynamoDb Driver - Get - Non-existent Key with default"""
        self._driver.initialize()
        assert_equal(self._driver.get('key_????:2', 'default?'), 'default?')

    @patch('logging.Logger.error')
    def test_non_existent_table_key(self, mock_logger):
        """LookupTables - Drivers - DynamoDb Driver - Get - Non-existent Table"""
        assert_raises(
            LookupTablesInitializationError,
            self._bad_driver.initialize
        )
        mock_logger.assert_any_call(
            (
                "LookupTable (dynamodb:table???): Encountered error while connecting with "
                "DynamoDB: 'Requested resource not found'"
            )
        )

    @patch('boto3.resource')
    @patch('logging.Logger.error')
    def test_botocore_read_timeout(self, mock_logger, boto_resource_fn_mock):
        """LookupTables - Drivers - DynamoDB Driver - Get - ReadTimeoutError"""
        boto_resource_fn_mock.return_value.Table.return_value.get_item.side_effect = \
            ReadTimeoutError(
                'TestPool', 'Test Read timed out.', endpoint_url='test/url'
            )

        self._driver.initialize()

        assert_raises(LookupTablesInitializationError, self._driver.get, 'bbbb:1')

        mock_logger.assert_any_call(
            'LookupTable (%s): Reading from DynamoDB timed out',
            'dynamodb:table_name'
        )

    @patch('logging.Logger.info')
    def test_refresh_on_first_read(self, mock_logger):
        """LookupTables - Drivers - DynamoDB Driver - Refresh - On First Read"""
        self._driver.initialize()

        assert_false('bbbb:1' in self._driver._dynamo_load_times)

        assert_equal(self._driver.get('bbbb:1', '?'), 'beeffedfeedbeefdeaddeafbeddab')

        mock_logger.assert_called_with(
            'LookupTable (%s): Key %s needs refresh, starting now. Last refresh: %s; Currently: %s',
            'dynamodb:table_name',
            'bbbb:1',
            0,
            ANY
        )

        assert_true('bbbb:1' in self._driver._dynamo_load_times)

    @patch('logging.Logger.debug')
    def test_barely_does_not_need_refresh(self, mock_logger):
        """LookupTables - Drivers - DynamoDB Driver - Refresh - Barely Does not need refresh"""
        self._driver.initialize()

        # Mess up some of the data so we fake that it's "stale"
        self._driver._dynamo_data['bbbb:1'] = 'stale'

        # Wind the "clock" back JUST before it needs a refresh
        self._driver._dynamo_load_times['bbbb:1'] = (
            datetime.utcnow() - timedelta(minutes=2, seconds=59)
        )

        assert_equal(self._driver.get('bbbb:1'), 'stale')

        mock_logger.assert_any_call(
            'LookupTable (%s): Key %s does not need refresh. Last refresh: %s; Currently: %s',
            'dynamodb:table_name', 'bbbb:1', ANY, ANY
        )

    @patch('logging.Logger.info')
    def test_needs_refresh(self, mock_logger):
        """LookupTables - Drivers - DynamoDB Driver - Refresh - Does need refresh"""
        self._driver.initialize()

        # Mess up some of the data so we fake that it's "stale"
        self._driver._dynamo_data['bbbb:1'] = 'stale'

        # Wind the "clock" back JUST before it needs a refresh
        self._driver._dynamo_load_times['bbbb:1'] = (
            datetime.utcnow() - timedelta(minutes=3, seconds=1)
        )

        assert_equal(self._driver.get('bbbb:1'), 'beeffedfeedbeefdeaddeafbeddab')

        mock_logger.assert_called_with(
            'LookupTable (%s): Key %s needs refresh, starting now. Last refresh: %s; Currently: %s',
            'dynamodb:table_name',
            'bbbb:1',
            ANY,
            ANY
        )


class TestDynamoDBDriver_MultiTable(object):
    """
    Tests the DynamoDB Driver, but it tests with a variety of drivers built over the same table,
    different columns.
    """
    # pylint: disable=protected-access,attribute-defined-outside-init,no-self-use
    def setup(self):
        """LookupTables - Setup S3 bucket mocking"""
        self.config = load_config('tests/unit/conf')

        self._dynamodb_mock = mock_dynamodb2()
        self._dynamodb_mock.start()

        self._int_driver = construct_persistence_driver(
            self.config['lookup_tables']['tables']['dinosaur_multi_int']
        )
        self._string_driver = construct_persistence_driver(
            self.config['lookup_tables']['tables']['dinosaur_multi_string']
        )
        self._dict_driver = construct_persistence_driver(
            self.config['lookup_tables']['tables']['dinosaur_multi_dict']
        )

        self._put_mock_tables()

    def _put_mock_tables(self):
        # Build a new dynamodb schema matching the tables configured
        boto3.client('dynamodb').create_table(
            AttributeDefinitions=[
                {
                    'AttributeName': 'Pkey',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'IntegerField',
                    'AttributeType': 'N'
                },
                {
                    'AttributeName': 'StringField',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'DictField',
                    'AttributeType': 'M'
                },
            ],
            KeySchema=[
                {
                    'AttributeName': 'Pkey',
                    'KeyType': 'HASH'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            },
            TableName='multi_table'
        )

        table = boto3.resource('dynamodb').Table('multi_table')
        with table.batch_writer() as batch:
            batch.put_item(
                Item={
                    'Pkey': 'aaaa-bbbb-cccc',
                    'IntegerField': 123,
                    'StringField': 'hello world!',
                    'DictField': {
                        'message': {
                            'depth': 'Will this work?'
                        }
                    }
                }
            )

    def teardown(self):
        self._dynamodb_mock.stop()

    def test_get_int(self):
        """LookupTables - Drivers - DynamoDb Multi Driver - Integer - Get Key"""
        self._int_driver.initialize()
        assert_equal(self._int_driver.get('aaaa-bbbb-cccc'), 123)

    def test_get_string(self):
        """LookupTables - Drivers - DynamoDb Multi Driver - String - Get Key"""
        self._string_driver.initialize()
        assert_equal(self._string_driver.get('aaaa-bbbb-cccc'), 'hello world!')

    def test_get_dict(self):
        """LookupTables - Drivers - DynamoDb Multi Driver - Dict - Get Key"""
        self._dict_driver.initialize()
        data = self._dict_driver.get('aaaa-bbbb-cccc')
        assert_equal(data['message']['depth'], 'Will this work?')

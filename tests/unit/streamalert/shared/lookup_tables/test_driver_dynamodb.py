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
from datetime import datetime
from unittest.mock import patch

import pytest
from botocore.exceptions import ReadTimeoutError
from moto import mock_dynamodb

from streamalert.shared.config import load_config
from streamalert.shared.lookup_tables.drivers_factory import \
    construct_persistence_driver
from streamalert.shared.lookup_tables.errors import \
    LookupTablesInitializationError
from tests.unit.helpers.aws_mocks import put_mock_dynamod_data


class TestDynamoDBDriver:
    """
    Tests the S3Driver

    This was largely ported over from test_lookup_tables.py from the old implementation.
    """
    # pylint: disable=protected-access,attribute-defined-outside-init,no-self-use

    def setup(self):
        """LookupTables - Setup S3 bucket mocking"""
        self.config = load_config('tests/unit/conf')
        self._dynamodb_mock = mock_dynamodb()
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
                ]
            },
            [
                {
                    'MyPartitionKey': 'aaaa',
                    'MySortKey': '1',
                    'MyValueKey': 'could_this_be_a_foo?',
                },
                {
                    'MyPartitionKey': 'aaaa',
                    'MySortKey': '2',
                    'MyValueKey': 'or_is_this_just_fantasy?',
                },
                {
                    'MyPartitionKey': 'aaaa',
                    'MySortKey': '3',
                    'MyValueKey': 'no_couldnt_be',
                },
                {
                    'MyPartitionKey': 'bbbb',
                    'MySortKey': '1',
                    'MyValueKey': 'beeffedfeedbeefdeaddeafbeddab',
                }
            ]
        )

    def teardown(self):
        self._dynamodb_mock.stop()

    @patch('logging.Logger.info')
    def test_initialize(self, mock_logger):
        """LookupTables - Drivers - DynamoDB Driver - Init"""
        self._driver.initialize()
        mock_logger.assert_any_call(
            'LookupTable (%s): Running initialization routine',
            'dynamodb:table_name'
        )

    def test_get(self):
        """LookupTables - Drivers - DynamoDB Driver - Get Key"""
        self._driver.initialize()
        assert self._driver.get('aaaa:1') == 'could_this_be_a_foo?'

    def test_get_2(self):
        """LookupTables - Drivers - DynamoDB Driver - Get Key #2"""
        self._driver.initialize()
        assert self._driver.get('aaaa:2') == 'or_is_this_just_fantasy?'

    def test_non_existent_key(self):
        """LookupTables - Drivers - DynamoDB Driver - Get - Non-existent Key with default"""
        self._driver.initialize()
        assert self._driver.get('key_????:2', 'default?') == 'default?'

    def test_non_existent_table_key(self):
        """LookupTables - Drivers - DynamoDB Driver - Get - Non-existent Table"""
        pytest.raises(
            LookupTablesInitializationError,
            self._bad_driver.initialize
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

        pytest.raises(LookupTablesInitializationError, self._driver.get, 'bbbb:1')

        mock_logger.assert_any_call(
            'LookupTable (%s): Reading from DynamoDB timed out',
            'dynamodb:table_name'
        )

    @patch('logging.Logger.info')
    def test_refresh_on_first_read(self, mock_logger):
        """LookupTables - Drivers - DynamoDB Driver - Refresh - On First Read"""
        self._driver.initialize()

        assert not self._driver._cache.has('bbbb:1')

        assert self._driver.get('bbbb:1', '?') == 'beeffedfeedbeefdeaddeafbeddab'

        mock_logger.assert_called_with(
            'LookupTable (%s): Key %s needs refresh, starting now.',
            'dynamodb:table_name',
            'bbbb:1'
        )

        assert self._driver._cache.has('bbbb:1')

    @patch('logging.Logger.debug')
    def test_barely_does_not_need_refresh(self, mock_logger):
        """LookupTables - Drivers - DynamoDB Driver - Refresh - Barely Does not need refresh"""
        self._driver.initialize()

        # Mess up some of the data so we fake that it's "stale"
        self._driver._cache._clock.time_machine(datetime(year=3000, month=1, day=1))
        self._driver._cache.set('bbbb:1', 'stale', 3)  # 3-minute ttl

        # Wind the "clock" forward JUST before it needs a refresh
        self._driver._cache._clock.time_machine(
            datetime(year=3000, month=1, day=1, minute=2, second=59)
        )

        assert self._driver.get('bbbb:1') == 'stale'

        mock_logger.assert_any_call(
            'LookupTable (%s): Key %s does not need refresh. TTL: %s',
            'dynamodb:table_name', 'bbbb:1', datetime(year=3000, month=1, day=1, minute=3)
        )

    @patch('logging.Logger.info')
    def test_needs_refresh(self, mock_logger):
        """LookupTables - Drivers - DynamoDB Driver - Refresh - Does need refresh"""
        self._driver.initialize()

        # Mess up some of the data so we fake that it's "stale"
        self._driver._cache._clock.time_machine(datetime(year=3000, month=1, day=1))
        self._driver._cache.set('bbbb:1', 'stale', 3)  # 3-minute ttl

        # Wind the "clock" forward JUST AFTER it needs a refresh
        self._driver._cache._clock.time_machine(
            datetime(year=3000, month=1, day=1, minute=3, second=1)
        )

        assert self._driver.get('bbbb:1') == 'beeffedfeedbeefdeaddeafbeddab'

        mock_logger.assert_called_with(
            'LookupTable (%s): Key %s needs refresh, starting now.',
            'dynamodb:table_name',
            'bbbb:1'
        )

    def test_set_commit_get(self, ):
        """LookupTables - Drivers - DynamoDB Driver - Set/Commmit - Can be refetched"""
        self._driver.initialize()

        self._driver.set('asdfasdf:1', 'A whole new world')
        self._driver.commit()
        assert self._driver.get('asdfasdf:1') == 'A whole new world'

    def test_invalid_key(self, ):
        """LookupTables - Drivers - DynamoDB Driver - Get - Invalid key raises"""
        self._driver.initialize()

        pytest.raises(LookupTablesInitializationError, self._driver.get, 'invalid-key')


# pylint: disable=protected-access,attribute-defined-outside-init,no-self-use,invalid-name
class TestDynamoDBDriver_MultiTable:
    """
    Tests the DynamoDB Driver, but it tests with a variety of drivers built over the same table,
    different columns.
    """

    def setup(self):
        """LookupTables - Setup S3 bucket mocking"""
        self.config = load_config('tests/unit/conf')

        self._dynamodb_mock = mock_dynamodb()
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
        put_mock_dynamod_data(
            'multi_table',
            {
                'AttributeDefinitions': [
                    {
                        'AttributeName': 'Pkey',
                        'AttributeType': 'S'
                    }
                ],
                'KeySchema': [
                    {
                        'AttributeName': 'Pkey',
                        'KeyType': 'HASH'
                    }
                ],
            },
            [
                {
                    'Pkey': 'aaaa-bbbb-cccc',
                    'IntegerField': 123,
                    'StringField': 'hello world!',
                    'DictField': {
                        'message': {
                            'depth': 'Will this work?'
                        }
                    }
                }
            ]
        )

    def teardown(self):
        self._dynamodb_mock.stop()

    def test_get_int(self):
        """LookupTables - Drivers - DynamoDB Multi Driver - Integer - Get Key"""
        self._int_driver.initialize()
        assert self._int_driver.get('aaaa-bbbb-cccc') == 123

    def test_get_string(self):
        """LookupTables - Drivers - DynamoDB Multi Driver - String - Get Key"""
        self._string_driver.initialize()
        assert self._string_driver.get('aaaa-bbbb-cccc') == 'hello world!'

    def test_get_dict(self):
        """LookupTables - Drivers - DynamoDB Multi Driver - Dict - Get Key"""
        self._dict_driver.initialize()
        data = self._dict_driver.get('aaaa-bbbb-cccc')
        assert data['message']['depth'] == 'Will this work?'

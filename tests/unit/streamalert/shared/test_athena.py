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
import collections
import os
# pylint: disable=protected-access,attribute-defined-outside-init
from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from streamalert.shared.athena import AthenaClient, AthenaQueryExecutionError
from streamalert.shared.config import load_config
from tests.unit.helpers.aws_mocks import MockAthenaClient


class TestAthenaClient:
    """Test class for AthenaClient"""
    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-west-1'})
    @patch('boto3.client', Mock(side_effect=lambda c, config=None: MockAthenaClient()))
    def setup(self):
        """Setup the AthenaClient tests"""

        self._db_name = 'test_database'
        config = load_config('tests/unit/conf/')
        prefix = config['global']['account']['prefix']

        self.client = AthenaClient(self._db_name, f's3://{prefix}-streamalert-athena-results',
                                   'unit-test')

    @patch('streamalert.shared.athena.datetime')
    def test_init_fix_bucket_path(self, date_mock):
        """Athena - Fix Bucket Path"""
        date_now = datetime.utcnow()
        date_mock.utcnow.return_value = date_now
        date_format = date_now.strftime('%Y/%m/%d/%H')
        expected_path = f's3://test-streamalert-athena-results/unit-test/{date_format}'
        with patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-west-1'}):
            client = AthenaClient(self._db_name, 'test-streamalert-athena-results', 'unit-test')
            assert client.results_path == expected_path

    def test_unique_values_from_query(self):
        """Athena - Unique Values from Query"""
        query = {
            'ResultSet': {
                'Rows': [
                    {
                        'Data': [{
                            'VarCharValue': 'foobar'
                        }]
                    },
                    {
                        'Data': [{
                            'VarCharValue': 'barfoo'
                        }]
                    },
                    {
                        'Data': [{
                            'VarCharValue': 'barfoo'
                        }]
                    },
                    {
                        'Data': [{
                            'VarCharValue': 'foobarbaz'
                        }]
                    },
                ]
            }
        }
        expected_result = {'foobar', 'barfoo', 'foobarbaz'}

        result = self.client._unique_values_from_query(query)
        assert collections.Counter(result) == collections.Counter(expected_result)

    def test_check_database_exists(self):
        """Athena - Check Database Exists"""
        self.client._client.results = [{'Data': [{'VarCharValue': self._db_name}]}]

        assert self.client.check_database_exists()

    def test_check_database_exists_invalid(self):
        """Athena - Check Database Exists - Does Not Exist"""
        self.client._client.results = None

        assert not self.client.check_database_exists()

    def test_check_table_exists(self):
        """Athena - Check Table Exists"""
        self.client._client.results = [{'Data': [{'VarCharValue': 'test_table'}]}]

        assert self.client.check_table_exists('test_table')

    def test_check_table_exists_invalid(self):
        """Athena - Check Table Exists - Does Not Exist"""
        self.client._client.results = None

        assert not self.client.check_table_exists('test_table')

    def test_get_table_partitions(self):
        """Athena - Get Table Partitions"""
        self.client._client.results = [
            {
                'Data': [{
                    'VarCharValue': 'dt=2018-12-10-10'
                }]
            },
            {
                'Data': [{
                    'VarCharValue': 'dt=2018-12-09-10'
                }]
            },
            {
                'Data': [{
                    'VarCharValue': 'dt=2018-12-09-10'
                }]
            },
            {
                'Data': [{
                    'VarCharValue': 'dt=2018-12-11-10'
                }]
            },
        ]

        expected_result = {'dt=2018-12-10-10', 'dt=2018-12-09-10', 'dt=2018-12-11-10'}

        result = self.client.get_table_partitions('test_table')
        assert collections.Counter(result) == collections.Counter(expected_result)

    def test_get_table_partitions_error(self):
        """Athena - Get Table Partitions, Exception"""
        self.client._client.raise_exception = True
        pytest.raises(AthenaQueryExecutionError, self.client.get_table_partitions, 'test_table')

    def test_drop_table(self):
        """Athena - Drop Table, Success"""
        assert self.client.drop_table('test_table')

    def test_drop_table_failure(self):
        """Athena - Drop Table, Failure"""
        self.client._client.raise_exception = True
        pytest.raises(AthenaQueryExecutionError, self.client.drop_table, 'test_table')

    @patch('streamalert.shared.athena.AthenaClient.drop_table')
    def test_drop_all_tables(self, drop_table_mock):
        """Athena - Drop All Tables, Success"""
        self.client._client.results = [
            {
                'Data': [{
                    'VarCharValue': 'table_01'
                }]
            },
            {
                'Data': [{
                    'VarCharValue': 'table_02'
                }]
            },
            {
                'Data': [{
                    'VarCharValue': 'table_02'
                }]
            },
        ]
        assert self.client.drop_all_tables()
        assert drop_table_mock.call_count == 2

    @patch('streamalert.shared.athena.AthenaClient.drop_table')
    def test_drop_all_tables_failure(self, drop_table_mock):
        """Athena - Drop All Tables, Failure"""
        self.client._client.results = [
            {
                'Data': [{
                    'VarCharValue': 'table_01'
                }]
            },
            {
                'Data': [{
                    'VarCharValue': 'table_02'
                }]
            },
            {
                'Data': [{
                    'VarCharValue': 'table_03'
                }]
            },
        ]
        drop_table_mock.side_effect = [True, True, False]
        assert not self.client.drop_all_tables()

    def test_drop_all_tables_exception(self):
        """Athena - Drop All Tables, Exception"""
        self.client._client.raise_exception = True
        pytest.raises(AthenaQueryExecutionError, self.client.drop_all_tables)

    def test_execute_query(self):
        """Athena - Execute Query"""
        self.client._client.raise_exception = True
        pytest.raises(AthenaQueryExecutionError, self.client._execute_query, 'BAD SQL')

    def test_execute_and_wait(self):
        """Athena - Execute and Wait"""
        self.client._client.results = [
            {
                'Data': [{
                    'VarCharValue': 'result'
                }]
            },
        ]
        result = self.client._execute_and_wait('SQL query')
        assert result in self.client._client.query_executions

    def test_execute_and_wait_failed(self):
        """Athena - Execute and Wait, Failed"""
        query = 'SQL query'
        self.client._client.result_state = 'FAILED'
        pytest.raises(AthenaQueryExecutionError, self.client._execute_and_wait, query)

    def test_query_result_paginator(self):
        """Athena - Query Result Paginator"""
        data = {'Data': [{'VarCharValue': 'result'}]}
        self.client._client.results = [
            data,
        ]

        items = list(self.client.query_result_paginator('test query'))
        assert len(items) == len([{'ResultSet': {'Rows': [data]}}] * 4)

    @pytest.mark.xfail(raises=AthenaQueryExecutionError)
    def test_query_result_paginator_error(self):
        """Athena - Query Result Paginator, Exception"""
        self.client._client.raise_exception = True
        list(self.client.query_result_paginator('test query'))

    def test_run_async_query(self):
        """Athena - Run Async Query, Success"""
        assert self.client.run_async_query('test query')

    def test_run_async_query_failure(self):
        """Athena - Run Async Query, Failure"""
        self.client._client.raise_exception = True
        pytest.raises(AthenaQueryExecutionError, self.client.run_async_query, 'test query')

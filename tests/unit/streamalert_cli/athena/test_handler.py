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
# pylint: disable=protected-access
from mock import patch
from nose.tools import assert_equal, assert_true

from streamalert.classifier.clients import FirehoseClient
from streamalert_cli.athena import handler

from tests.unit.helpers.aws_mocks import MockAthenaClient
from tests.unit.helpers.config import athena_cli_basic_config, MockCLIConfig


class TestAthenaCli:
    """Class to test Athena CLI"""

    @staticmethod
    def teardown():
        """Clean up after each test"""
        FirehoseClient._ENABLED_LOGS.clear()

    @staticmethod
    def test_construct_create_table_statement():
        """CLI - Athena Construct Create Table Statement"""
        # pylint: disable=protected-access
        schema = {
            'value01': 'string',
            'value02': 'integer',
            'value03': {
                'value04': 'boolean',
                'value05': 'float'
            }
        }

        expected_result = ('CREATE EXTERNAL TABLE table-name (value01 string, value02 integer, '
                           'value03 struct<value04:boolean, value05:float>) '
                           'PARTITIONED BY (dt string) '
                           'STORED AS PARQUET '
                           'LOCATION \'s3://bucket-name/table-name/\'')

        result = handler._construct_create_table_statement(schema, 'table-name', 'bucket-name')
        assert_equal(result, expected_result)

    @staticmethod
    def test_rebuild_partitions():
        """CLI - Athena rebuild partitions helper"""

        with patch('streamalert.shared.athena.boto3') as mock_athena:
            mock_show_partitions_result = [
                {'Data': [{'VarCharValue': 'dt=2019-12-04-05'}]},
                {'Data': [{'VarCharValue': 'dt=2019-12-03-22'}]},
                {'Data': [{'VarCharValue': 'dt=2019-12-03-23'}]},
                {'Data': [{'VarCharValue': 'dt=2019-12-03-20'}]},
                {'Data': [{'VarCharValue': 'dt=2019-12-04-01'}]}
            ]

            mock_show_table_result = []
            mock_athena.client.side_effect = [
                MockAthenaClient(results=mock_show_partitions_result),
                MockAthenaClient(results=mock_show_table_result)
            ]

            config = MockCLIConfig(config=athena_cli_basic_config())

            table = 'unit_my_test'
            bucket = 'bucket'
            assert_true(handler.rebuild_partitions(table, bucket, config))

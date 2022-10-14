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
# pylint: disable=protected-access
from unittest.mock import Mock, patch

from streamalert.shared.firehose import FirehoseClient
from streamalert_cli.athena import handler
from streamalert_cli.config import CLIConfig
from tests.unit.helpers.aws_mocks import MockAthenaClient
from tests.unit.helpers.config import MockCLIConfig, athena_cli_basic_config


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
        assert result == expected_result

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
            assert handler.rebuild_partitions(table, bucket, config)

    @staticmethod
    @patch('streamalert.shared.athena.AthenaClient.check_table_exists', Mock(return_value=False))
    @patch('streamalert.shared.athena.AthenaClient.run_query', Mock(return_value=True))
    def test_create_table_with_dots():
        """CLI - Athena create table helper when log name contains dots"""
        config = CLIConfig(config_path='tests/unit/conf')
        config['global']['infrastructure']['firehose']['enabled_logs'] = {
            'test:log.name.with.dots': {}
        }

        assert handler.create_table(
            'test:log.name.with.dots',
            'bucket',
            config
        )

    @staticmethod
    @patch('streamalert.shared.athena.AthenaClient.check_table_exists', Mock(return_value=False))
    @patch('streamalert.shared.athena.AthenaClient.run_query', Mock(return_value=True))
    def test_create_table_with_underscores():
        """CLI - Athena create table helper when log name contains underscores"""
        config = CLIConfig(config_path='tests/unit/conf')
        config['global']['infrastructure']['firehose']['enabled_logs'] = {
            'cloudwatch:test_match_types': {}
        }

        assert handler.create_table(
            'cloudwatch:test_match_types',
            'bucket',
            config
        )

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
from unittest.mock import patch

from streamalert.shared.firehose import FirehoseClient
from streamalert_cli.athena import helpers
from streamalert_cli.config import CLIConfig

CONFIG = CLIConfig(config_path='tests/unit/conf')


def test_generate_athena_schema_simple():
    """CLI - Generate Athena schema: simple"""

    log_schema = CONFIG['logs']['unit_test_simple_log']['schema']
    athena_schema = helpers.logs_schema_to_athena_schema(log_schema)

    expected_athena_schema = {
        '`unit_key_01`': 'bigint',
        '`unit_key_02`': 'string'
    }

    assert athena_schema == expected_athena_schema


def test_generate_athena_schema_special_key():
    """CLI - Generate Athena schema: special key"""

    log_schema = CONFIG['logs']['test_log_type_json']['schema']
    athena_schema = helpers.logs_schema_to_athena_schema(log_schema)

    expected_athena_schema = {
        '`key1`': 'array<string>',
        '`key2`': 'string',
        '`key3`': 'bigint',
        '`key9`': 'boolean',
        '`key10`': 'map<string,string>',
        '`key11`': 'decimal(10,3)'
    }

    assert athena_schema == expected_athena_schema


def test_generate_athena_schema_nested():
    """CLI - Generate Athena schema: nested"""

    log_schema = CONFIG['logs']['test_log_type_json_nested_with_data']['schema']
    athena_schema = helpers.logs_schema_to_athena_schema(log_schema)

    expected_athena_schema = {
        '`date`': 'string',
        '`unixtime`': 'bigint',
        '`host`': 'string',
        '`application`': 'string',
        '`environment`': 'string',
        '`data`': {
            '`category`': 'string',
            '`type`': 'bigint',
            '`source`': 'string'
        }
    }

    assert athena_schema == expected_athena_schema


def test_add_partition_statements():
    """CLI - Athena Add Partition Statement"""
    partitions = {
        'dt=2017-12-01-01',
        'dt=2016-12-01-02',
        'dt=2018-12-01-05',
        'dt=2013-12-01-04',
    }

    expected_result = ("ALTER TABLE test ADD IF NOT EXISTS "
                       "PARTITION (dt = '2013-12-01-04') "
                       "LOCATION 's3://bucket/test/2013/12/01/04' "
                       "PARTITION (dt = '2016-12-01-02') "
                       "LOCATION 's3://bucket/test/2016/12/01/02' "
                       "PARTITION (dt = '2017-12-01-01') "
                       "LOCATION 's3://bucket/test/2017/12/01/01' "
                       "PARTITION (dt = '2018-12-01-05') "
                       "LOCATION 's3://bucket/test/2018/12/01/05'")

    results = helpers.add_partition_statements(partitions, 'bucket', 'test')
    results_copy = list(results)
    assert len(results_copy) == 1
    assert results_copy[0] == expected_result


@patch.object(helpers, 'MAX_QUERY_LENGTH', 256)
def test_add_partition_statements_exceed_length():
    """CLI - Athena Add Partition Statement when statement exceed max query length"""
    partitions = {
        'dt=2017-12-01-01',
        'dt=2016-12-01-02',
        'dt=2018-12-01-05',
        'dt=2013-12-01-04',
    }

    results = helpers.add_partition_statements(partitions, 'bucket', 'test')
    results_copy = list(results)
    assert len(results_copy) == 2

    expected_result_0 = ("ALTER TABLE test ADD IF NOT EXISTS "
                         "PARTITION (dt = '2013-12-01-04') "
                         "LOCATION 's3://bucket/test/2013/12/01/04' "
                         "PARTITION (dt = '2016-12-01-02') "
                         "LOCATION 's3://bucket/test/2016/12/01/02'")
    expected_result_1 = ("ALTER TABLE test ADD IF NOT EXISTS "
                         "PARTITION (dt = '2017-12-01-01') "
                         "LOCATION 's3://bucket/test/2017/12/01/01' "
                         "PARTITION (dt = '2018-12-01-05') "
                         "LOCATION 's3://bucket/test/2018/12/01/05'")
    assert results_copy[0] == expected_result_0
    assert results_copy[1] == expected_result_1

# pylint: disable=protected-access


def test_generate_data_table_schema():
    """CLI - Athena generate_data_table_schema helper"""
    config = CLIConfig(config_path='tests/unit/conf')
    config['global']['infrastructure']['firehose']['enabled_logs'] = {
        'test:log.name.with.dots': {}
    }

    assert helpers.generate_data_table_schema(config, 'test:log.name.with.dots')
    FirehoseClient._ENABLED_LOGS.clear()

# pylint: disable=protected-access


def test_generate_data_table_schema_2():
    """CLI - Athena generate_data_table_schema helper"""
    config = CLIConfig(config_path='tests/unit/conf')
    config['global']['infrastructure']['firehose']['enabled_logs'] = {
        'cloudwatch:test_match_types': {}
    }

    assert helpers.generate_data_table_schema(config, 'cloudwatch:test_match_types')
    FirehoseClient._ENABLED_LOGS.clear()


def test_generate_artifact_table_schema():
    """CLI - Athena test generate_artifact_table_schema helper"""
    result = helpers.generate_artifacts_table_schema()

    expected_result = [
        ('function', 'string'),
        ('source_type', 'string'),
        ('streamalert_record_id', 'string'),
        ('type', 'string'),
        ('value', 'string')
    ]

    assert result == expected_result

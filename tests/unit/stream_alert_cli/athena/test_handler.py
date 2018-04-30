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
from nose.tools import assert_equal

from stream_alert_cli.config import CLIConfig

from stream_alert_cli.athena import handler, helpers

CONFIG = CLIConfig(config_path='tests/unit/conf')


def test_generate_athena_schema_simple():
    """CLI - Generate Athena schema: simple"""

    log_schema = CONFIG['logs']['unit_test_simple_log']['schema']
    athena_schema = helpers.logs_schema_to_athena_schema(log_schema)

    expected_athena_schema = {
        '`unit_key_01`': 'bigint',
        '`unit_key_02`': 'string'
    }

    assert_equal(athena_schema, expected_athena_schema)


def test_generate_athena_schema_special_key():
    """CLI - Generate Athena schema: special key"""

    log_schema = CONFIG['logs']['test_log_type_json']['schema']
    athena_schema = helpers.logs_schema_to_athena_schema(log_schema)

    expected_athena_schema = {
        '`key1`': 'array<string>',
        '`key2`': 'string',
        '`key3`': 'bigint',
        '`key9`': 'boolean',
        '`key10`': 'map<string, string>',
        '`key11`': 'decimal(10,3)'
    }

    assert_equal(athena_schema, expected_athena_schema)


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

    assert_equal(athena_schema, expected_athena_schema)


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
                       'value03 struct<value04:boolean, value05:float>) PARTITIONED BY '
                       '(dt string) ROW FORMAT SERDE \'org.openx.data.jsonserde.JsonSerDe\' '
                       'WITH SERDEPROPERTIES (\'ignore.malformed.json\' = \'true\') '
                       'LOCATION \'s3://bucket-name/table-name/\'')

    result = handler._construct_create_table_statement(schema, 'table-name', 'bucket-name')
    assert_equal(result, expected_result)

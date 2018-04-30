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

from stream_alert_cli.athena import handler


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

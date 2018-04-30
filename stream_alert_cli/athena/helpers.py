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
import re


PARTITION_PARTS = re.compile(
    r'dt=(?P<year>\d{4})\-(?P<month>\d{2})\-(?P<day>\d{2})\-(?P<hour>\d{2})')

# The returned partition from the SHOW PARTITIONS command is dt=YYYY-MM-DD-HH,
# But when re-creating new partitions this value must be quoted
PARTITION_STMT = ("PARTITION (dt = '{year}-{month}-{day}-{hour}') "
                  "LOCATION 's3://{bucket}/{table_name}/{year}/{month}/{day}/{hour}'")

# How to map log schema types to Athena/Hive types
SCHEMA_TYPE_MAPPING = {
    'string': 'string',
    'integer': 'bigint',
    'boolean': 'boolean',
    'float': 'decimal(10,3)',
    dict: 'map<string, string>',
    list: 'array<string>'
}


def add_partition_statement(partitions, bucket, table_name):
    """Generate ALTER TABLE commands from existing partitions.

    Args:
        partitions (set): The unique set of partitions gathered from Athena
        bucket (str): The bucket name
        table_name (str): The name of the Athena table

    Returns:
        str: The ALTER TABLE statement to add the new partitions
    """
    statements = ['ALTER TABLE {} ADD IF NOT EXISTS'.format(table_name)]
    fmt_values = {
        'bucket': bucket,
        'table_name': table_name
    }

    for partition in sorted(partitions):
        parts = PARTITION_PARTS.match(partition)
        if not parts:
            continue

        fmt_values.update(parts.groupdict())

        statements.append(PARTITION_STMT.format(**fmt_values))

    return ' '.join(statements)


def logs_schema_to_athena_schema(log_schema):
    """Convert streamalert log schema to athena schema

    Args:
        log_schema (dict): StreamAlert log schema object.

    Returns:
        athena_schema (dict): Equivalent Athena schema used for generating create table statement
    """

    athena_schema = {}

    for key_name, key_type in log_schema.iteritems():
        key_name = '`{}`'.format(key_name)
        if key_type == {}:
            # For empty dicts
            athena_schema[key_name] = SCHEMA_TYPE_MAPPING[dict]
        elif key_type == []:
            # For empty array
            athena_schema[key_name] = SCHEMA_TYPE_MAPPING[list]
        elif isinstance(key_type, dict):
            # For recursion
            athena_schema[key_name] = logs_schema_to_athena_schema(key_type)
        else:
            athena_schema[key_name] = SCHEMA_TYPE_MAPPING[key_type]

    return athena_schema


def unique_values_from_query(query_result):
    """Simplify Athena query results into a set of values.

    Useful for listing tables, partitions, databases, enable_metrics

    Args:
        query_result (dict): The result of run_athena_query

    Returns:
        set: Unique values from the query result
    """
    return {
        value
        for row in query_result['ResultSet']['Rows'] for result in row['Data']
        for value in result.values()
    }

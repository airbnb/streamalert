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
import re

from streamalert.shared.alert import Alert
from streamalert.shared.artifact_extractor import Artifact
from streamalert.shared.firehose import FirehoseClient
from streamalert.shared.logger import get_logger
from streamalert_cli.helpers import record_to_schema

LOGGER = get_logger(__name__)

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
    dict: 'map<string,string>',
    list: 'array<string>'
}

# Athena query statement length limit
MAX_QUERY_LENGTH = 262144


def add_partition_statements(partitions, bucket, table_name):
    """Generate ALTER TABLE commands from existing partitions. It wil yield Athena
    statement string(s), the length of each string should be less than Athena query
    statement length limit, 262144 bytes.
    https://docs.aws.amazon.com/athena/latest/ug/service-limits.html

    Args:
        partitions (set): The unique set of partitions gathered from Athena
        bucket (str): The bucket name
        table_name (str): The name of the Athena table

    Yields:
        string: The ALTER TABLE statements to add the new partitions
    """
    # Each add partition statement starting with "ALTER TABLE"
    initial_statement = f'ALTER TABLE {table_name} ADD IF NOT EXISTS'
    initial_statement_len = len(initial_statement)

    # The statement will be stored in a list of string format before join into a string
    statement = [initial_statement]
    statement_len = initial_statement_len

    fmt_values = {'bucket': bucket, 'table_name': table_name}

    for partition in sorted(partitions):
        parts = PARTITION_PARTS.match(partition)
        if not parts:
            continue

        fmt_values |= parts.groupdict()
        partition_stmt = PARTITION_STMT.format(**fmt_values)
        partition_stmt_len = len(partition_stmt)

        # It will add a space between sub strings when join the whole statement
        space_count = len(statement)

        # Monitor the lenght of whole statement and make sure it won't exceed the limit
        if statement_len + partition_stmt_len + space_count >= MAX_QUERY_LENGTH:
            # If the length of whole statement about to exceed the limit, yield
            # the statement and reset it for rest of partitions
            yield ' '.join(statement)
            statement = [initial_statement]
            statement_len = initial_statement_len

        statement_len += partition_stmt_len
        statement.append(partition_stmt)

    yield ' '.join(statement)


def logs_schema_to_athena_schema(log_schema, ddl_statement=True):
    """Convert streamalert log schema to athena schema

    Args:
        log_schema (dict): StreamAlert log schema object.
        ddl_statement (bool): Indicate if the Athena table created by Athena
            DDL query or terraform aws_glue_catalog_table resource

    Returns:
        athena_schema (dict): Equivalent Athena schema used for generating create table statement
    """

    athena_schema = {}

    for key_name, key_type in log_schema.items():
        if ddl_statement:
            # Backticks are needed for backward compatibility when creating Athena
            # table via Athena DDL query.
            key_name = f'`{key_name}`'
        if key_type == {}:
            # For empty dicts
            athena_schema[key_name] = SCHEMA_TYPE_MAPPING[dict]
        elif key_type == []:
            # For empty array
            athena_schema[key_name] = SCHEMA_TYPE_MAPPING[list]
        elif isinstance(key_type, dict):
            # For recursion
            athena_schema[key_name] = logs_schema_to_athena_schema(key_type, ddl_statement)
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
        for value in list(result.values())
    }


def format_schema_tf(schema):
    """Format schema for an Athena table for terraform.

    Args:
        schema (dict): Equivalent Athena schema used for generating create table statement

    Returns:
        formatted_schema (list(tuple))
    """
    # Construct the main Athena Schema
    formatted_schema = []
    for key_name in sorted(schema.keys()):
        key_type = schema[key_name]
        if isinstance(key_type, str):
            formatted_schema.append((key_name.lower(), key_type))
        elif isinstance(key_type, dict):
            struct_schema = ','.join(f'{sub_key.lower()}:{key_type[sub_key]}'
                                     for sub_key in sorted(key_type.keys()))
            formatted_schema.append((key_name.lower(), f'struct<{struct_schema}>'))

    return formatted_schema


def generate_alerts_table_schema():
    """Generate the schema for alerts table in terraform by using a fake alert

    Returns:
        athena_schema (dict): Equivalent Athena schema used for generating create table statement
    """
    alert = Alert('temp_rule_name', {}, {})
    output = alert.output_dict()
    schema = record_to_schema(output)
    athena_schema = logs_schema_to_athena_schema(schema, False)

    return format_schema_tf(athena_schema)


def generate_data_table_schema(config, table, schema_override=None):
    """Generate the schema for data table in terraform

    Args:
        config (CLIConfig): Loaded StreamAlert config
        table (string): The name of data table

    Returns:
        athena_schema (dict): Equivalent Athena schema used for generating create table statement
    """
    enabled_logs = FirehoseClient.load_enabled_log_sources(
        config['global']['infrastructure']['firehose'], config['logs'])

    # Convert special characters in schema name to underscores
    sanitized_table_name = FirehoseClient.sanitized_value(table)

    # Check that the log type is enabled via Firehose
    if sanitized_table_name not in enabled_logs:
        LOGGER.error('Table name %s missing from configuration or '
                     'is not enabled.', sanitized_table_name)
        return None

    log_info = config['logs'][enabled_logs.get(sanitized_table_name)]

    schema = dict(log_info['schema'])
    sanitized_schema = FirehoseClient.sanitize_keys(schema)

    athena_schema = logs_schema_to_athena_schema(sanitized_schema, False)

    if configuration_options := log_info.get('configuration'):
        if envelope_keys := configuration_options.get('envelope_keys'):
            sanitized_envelope_key_schema = FirehoseClient.sanitize_keys(envelope_keys)
            # Note: this key is wrapped in backticks to be Hive compliant
            athena_schema['streamalert:envelope_keys'] = logs_schema_to_athena_schema(
                sanitized_envelope_key_schema, False)

    # Handle Schema overrides
    #   This is useful when an Athena schema needs to differ from the normal log schema
    if schema_override:
        for override in schema_override:
            column_name, column_type = override.split('=')
            # Columns are escaped to avoid Hive issues with special characters
            column_name = f'{column_name}'
            if column_name in athena_schema:
                athena_schema[column_name] = column_type
                LOGGER.info('Applied schema override: %s:%s', column_name, column_type)
            else:
                LOGGER.error('Schema override column %s not found in Athena Schema, skipping',
                             column_name)

    return format_schema_tf(athena_schema)


def generate_artifacts_table_schema():
    """Generate the schema for artifacts table in terraform by using a test artifact instance

    Returns:
        athena_schema (dict): Equivalent Athena schema used for generating create table statement
    """
    artifact = artifact = Artifact(normalized_type='test_normalized_type',
                                   value='test_value',
                                   source_type='test_source_type',
                                   record_id='test_record_id',
                                   function=None)
    schema = record_to_schema(artifact.artifact)
    athena_schema = logs_schema_to_athena_schema(schema, False)

    return format_schema_tf(athena_schema)

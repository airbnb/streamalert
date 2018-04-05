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
from stream_alert.athena_partition_refresh.main import StreamAlertAthenaClient
from stream_alert.athena_partition_refresh import helpers as athena_helpers
from stream_alert.rule_processor.firehose import StreamAlertFirehose
from stream_alert.shared.alert import Alert
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.helpers import continue_prompt, record_to_schema
from stream_alert_cli.athena import helpers as handler_helpers


CREATE_TABLE_STATEMENT = ('CREATE EXTERNAL TABLE {table_name} ({schema}) '
                          'PARTITIONED BY (dt string) '
                          'ROW FORMAT SERDE \'org.openx.data.jsonserde.JsonSerDe\' '
                          'WITH SERDEPROPERTIES ( \'ignore.malformed.json\' = \'true\') '
                          'LOCATION \'s3://{bucket}/{table_name}/\'')

MAX_QUERY_LENGTH = 262144


def rebuild_partitions(table, bucket, config):
    """Rebuild an Athena table's partitions

    Steps:
      - Get the list of current partitions
      - Destroy existing table
      - Re-create tables
      - Re-create partitions

    Args:
        table (str): The name of the table being rebuilt
        bucket (str): The s3 bucket to be used as the location for Athena data
        table_type (str): The type of table being refreshed
            Types of 'data' and 'alert' are accepted, but only 'data' is implemented
        config (CLIConfig): Loaded StreamAlert CLI
    """
    athena_client = StreamAlertAthenaClient(config, results_key_prefix='stream_alert_cli')

    sa_firehose = StreamAlertFirehose(config['global']['account']['region'],
                                      config['global']['infrastructure']['firehose'],
                                      config['logs'])

    sanitized_table_name = sa_firehose.firehose_log_name(table)

    # Get the current set of partitions
    partition_success, partitions = athena_client.run_athena_query(
        query='SHOW PARTITIONS {}'.format(sanitized_table_name),
        database=athena_client.sa_database
    )
    if not partition_success:
        LOGGER_CLI.error('An error occurred when loading partitions for %s',
                         sanitized_table_name)
        return

    unique_partitions = athena_helpers.unique_values_from_query(partitions)

    # Drop the table
    LOGGER_CLI.info('Dropping table %s', sanitized_table_name)
    drop_success, _ = athena_client.run_athena_query(
        query='DROP TABLE {}'.format(sanitized_table_name),
        database=athena_client.sa_database
    )
    if not drop_success:
        LOGGER_CLI.error('An error occurred when dropping the %s table', sanitized_table_name)
        return

    LOGGER_CLI.info('Dropped table %s', sanitized_table_name)

    new_partitions_statement = athena_helpers.partition_statement(
        unique_partitions, bucket, sanitized_table_name)

    # Make sure our new alter table statement is within the query API limits
    if len(new_partitions_statement) > MAX_QUERY_LENGTH:
        LOGGER_CLI.error('Partition statement too large, writing to local file')
        with open('partitions_{}.txt'.format(sanitized_table_name), 'w') as partition_file:
            partition_file.write(new_partitions_statement)
        return

    # Re-create the table with previous partitions
    create_table(table, bucket, config)

    LOGGER_CLI.info('Creating %d new partitions for %s',
                    len(unique_partitions), sanitized_table_name)
    new_part_success, _ = athena_client.run_athena_query(
        query=new_partitions_statement,
        database=athena_client.sa_database
    )
    if not new_part_success:
        LOGGER_CLI.error('Error re-creating new partitions for %s', sanitized_table_name)
        return

    LOGGER_CLI.info('Successfully rebuilt partitions for %s', sanitized_table_name)


def drop_all_tables(config):
    """Drop all 'streamalert' Athena tables

    Used when cleaning up an existing deployment

    Args:
        config (CLIConfig): Loaded StreamAlert CLI
    """
    if not continue_prompt(message='Are you sure you want to drop all Athena tables?'):
        return

    athena_client = StreamAlertAthenaClient(config, results_key_prefix='stream_alert_cli')

    success, all_tables = athena_client.run_athena_query(
        query='SHOW TABLES',
        database=athena_client.sa_database
    )
    if not success:
        LOGGER_CLI.error('There was an issue getting all tables')
        return

    unique_tables = athena_helpers.unique_values_from_query(all_tables)

    for table in unique_tables:
        success, all_tables = athena_client.run_athena_query(
            query='DROP TABLE {}'.format(table),
            database=athena_client.sa_database
        )
        if not success:
            LOGGER_CLI.error('Unable to drop the %s table', table)
        else:
            LOGGER_CLI.info('Dropped %s', table)


def _construct_create_table_statement(schema, table_name, bucket):
    """Convert a dictionary based Athena schema to a Hive DDL statement

    Args:
        schema (dict): The sanitized Athena schema
        table_name (str): The name of the Athena table to create
        bucket (str): The S3 bucket containing the data

    Returns:
        str: The Hive DDL CREATE TABLE expression
    """
    # Construct the main Athena Schema
    schema_statement = ''
    for key_name, key_type in schema.iteritems():
        if isinstance(key_type, str):
            schema_statement += '{0} {1},'.format(key_name, key_type)
        # Account for nested structs
        elif isinstance(key_type, dict):
            struct_schema = ''.join([
                '{0}:{1},'.format(sub_key, sub_type) for sub_key, sub_type in key_type.iteritems()
            ])
            nested_schema_statement = '{0} struct<{1}>, '.format(
                key_name,
                # Use the minus index to remove the last comma
                struct_schema[:-1])

            schema_statement += nested_schema_statement

    return CREATE_TABLE_STATEMENT.format(
        table_name=table_name,
        # Remove the last comma from the generated statement
        schema=schema_statement[:-1],
        bucket=bucket)


def create_table(table, bucket, config, schema_override=None):
    """Create a 'streamalert' Athena table

    Args:
        table (str): The name of the table being rebuilt
        bucket (str): The s3 bucket to be used as the location for Athena data
        table_type (str): The type of table being refreshed
        config (CLIConfig): Loaded StreamAlert CLI
        schema_override (set): An optional set of key=value pairs to be used for
            overriding the configured column_name=value_type.
    """
    athena_client = StreamAlertAthenaClient(config, results_key_prefix='stream_alert_cli')

    sa_firehose = StreamAlertFirehose(config['global']['account']['region'],
                                      config['global']['infrastructure']['firehose'],
                                      config['logs'])

    # Convert special characters in schema name to underscores
    sanitized_table_name = sa_firehose.firehose_log_name(table)

    # Check that the log type is enabled via Firehose
    if sanitized_table_name not in sa_firehose.enabled_logs:
        LOGGER_CLI.error('Table name %s missing from configuration or '
                         'is not enabled.', sanitized_table_name)
        return

    # Check if the table exists
    if athena_client.check_table_exists(sanitized_table_name, True):
        LOGGER_CLI.info('The \'%s\' table already exists.', sanitized_table_name)
        return

    if table == 'alerts':
        # get a fake alert so we can get the keys needed and their types
        alert = Alert('temp_rule_name', {}, {})
        output = alert.output_dict()
        schema = record_to_schema(output)
        athena_schema = handler_helpers.to_athena_schema(schema)

        query = _construct_create_table_statement(
            schema=athena_schema, table_name=table, bucket=bucket)

    else: # all other tables are log types

        log_info = config['logs'][table.replace('_', ':', 1)]

        schema = dict(log_info['schema'])
        sanitized_schema = StreamAlertFirehose.sanitize_keys(schema)

        athena_schema = handler_helpers.to_athena_schema(sanitized_schema)

        # Add envelope keys to Athena Schema
        configuration_options = log_info.get('configuration')
        if configuration_options:
            envelope_keys = configuration_options.get('envelope_keys')
            if envelope_keys:
                sanitized_envelope_key_schema = StreamAlertFirehose.sanitize_keys(envelope_keys)
                # Note: this key is wrapped in backticks to be Hive compliant
                athena_schema['`streamalert:envelope_keys`'] = handler_helpers.to_athena_schema(
                    sanitized_envelope_key_schema)

        # Handle Schema overrides
        #   This is useful when an Athena schema needs to differ from the normal log schema
        if schema_override:
            for override in schema_override:
                column_name, column_type = override.split('=')
                if not all([column_name, column_type]):
                    LOGGER_CLI.error('Invalid schema override [%s], use column_name=type format',
                                     override)

                # Columns are escaped to avoid Hive issues with special characters
                column_name = '`{}`'.format(column_name)
                if column_name in athena_schema:
                    athena_schema[column_name] = column_type
                    LOGGER_CLI.info('Applied schema override: %s:%s', column_name, column_type)
                else:
                    LOGGER_CLI.error(
                        'Schema override column %s not found in Athena Schema, skipping',
                        column_name)

        query = _construct_create_table_statement(
            schema=athena_schema, table_name=sanitized_table_name, bucket=bucket)


    create_table_success, _ = athena_client.run_athena_query(
        query=query,
        database=athena_client.sa_database
    )

    if not create_table_success:
        LOGGER_CLI.error('The %s table could not be created', sanitized_table_name)
        return

    # Update the CLI config
    config['lambda']['athena_partition_refresh_config'] \
          ['buckets'][bucket] = sanitized_table_name
    config.write()

    LOGGER_CLI.info('The %s table was successfully created!', sanitized_table_name)


def athena_handler(options, config):
    """Main Athena handler

    Args:
        options (namedtuple): The parsed args passed from the CLI
        config (CLIConfig): Loaded StreamAlert CLI
    """
    if options.subcommand == 'init':
        config.generate_athena()

    elif options.subcommand == 'rebuild-partitions':
        rebuild_partitions(
            options.table_name,
            options.bucket,
            config)

    elif options.subcommand == 'drop-all-tables':
        drop_all_tables(config)

    elif options.subcommand == 'create-table':
        create_table(
            options.table_name,
            options.bucket,
            config,
            options.schema_override)

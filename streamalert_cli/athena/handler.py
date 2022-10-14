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
from streamalert.shared.alert import Alert
from streamalert.shared.athena import AthenaClient
from streamalert.shared.config import (firehose_alerts_bucket,
                                       firehose_data_bucket)
from streamalert.shared.firehose import FirehoseClient
from streamalert.shared.logger import get_logger
from streamalert.shared.utils import get_data_file_format, get_database_name
from streamalert_cli.athena import helpers
from streamalert_cli.helpers import continue_prompt, record_to_schema
from streamalert_cli.utils import (CLICommand, UniqueSortedListAction,
                                   generate_subparser, set_parser_epilog)

LOGGER = get_logger(__name__)

CREATE_TABLE_STATEMENT = ('CREATE EXTERNAL TABLE {table_name} ({schema}) '
                          'PARTITIONED BY (dt string) '
                          '{file_format} '
                          'LOCATION \'s3://{bucket}/{table_name}/\'')
STORE_FORMAT_JSON = ('ROW FORMAT SERDE \'org.openx.data.jsonserde.JsonSerDe\' '
                     'WITH SERDEPROPERTIES (\'ignore.malformed.json\' = \'true\')')

STORE_FORMAT_PARQUET = 'STORED AS PARQUET'


class AthenaCommand(CLICommand):
    description = 'Perform actions related to Athena'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add athena subparser: manage.py athena [subcommand]"""
        athena_subparsers = subparser.add_subparsers(dest='athena subcommand', required=True)

        cls._setup_athena_create_table_subparser(athena_subparsers)
        cls._setup_athena_rebuild_subparser(athena_subparsers)
        cls._setup_athena_drop_all_subparser(athena_subparsers)

    @classmethod
    def _setup_athena_create_table_subparser(cls, subparsers):
        """Add the athena create-table subparser: manage.py athena create-table [options]"""
        athena_create_table_parser = generate_subparser(subparsers,
                                                        'create-table',
                                                        description='Create an Athena table',
                                                        subcommand=True)

        set_parser_epilog(athena_create_table_parser,
                          epilog=('''\
                Examples:

                    manage.py athena create-table \\
                      --bucket s3.bucket.name \\
                      --table-name my_athena_table
                '''))

        cls._add_default_athena_args(athena_create_table_parser)

        # Validate the provided schema-override options
        def _validate_override(val):
            """Make sure the input is in the format column_name=type"""
            err = ('Invalid override expression [{}]. The proper format is '
                   '"column_name=value_type"').format(val)
            if '=' not in val:
                raise athena_create_table_parser.error(err)

            if len(val.split('=')) != 2:
                raise athena_create_table_parser.error(err)

        athena_create_table_parser.add_argument(
            '--schema-override',
            nargs='+',
            help=('Value types to override with new types in the log schema. '
                  'The provided input should be space-separated '
                  'directives like "column_name=value_type"'),
            action=UniqueSortedListAction,
            default=[],
            type=_validate_override)

    @classmethod
    def _setup_athena_rebuild_subparser(cls, subparsers):
        """
        Add the athena rebuild-partitions subparser:

        $ manage.py athena rebuild-partitions [options]
        """
        athena_rebuild_parser = generate_subparser(
            subparsers,
            'rebuild-partitions',
            description='Rebuild the partitions for an Athena table',
            subcommand=True)

        set_parser_epilog(athena_rebuild_parser,
                          epilog=('''\
                Examples:

                    manage.py athena rebuild-partitions \\
                      --bucket s3.bucket.name \\
                      --table-name my_athena_table
                '''))

        cls._add_default_athena_args(athena_rebuild_parser)

    @staticmethod
    def _setup_athena_drop_all_subparser(subparsers):
        """Add the athena drop-all-tables subparser: manage.py athena drop-all-tables"""
        generate_subparser(subparsers,
                           'drop-all-tables',
                           description='Drop all tables from an Athena database',
                           subcommand=True)

    @staticmethod
    def _add_default_athena_args(athena_parser):
        """Adds the default required arguments for athena subcommands (bucket and table)"""
        athena_parser.add_argument(
            '-b',
            '--bucket',
            help=('Name of the S3 bucket where log data is located. If not supplied, default will '
                  'be "<prefix>-streamalert-data"'))

        athena_parser.add_argument('-t',
                                   '--table-name',
                                   help=('Name of the Athena table to create. '
                                         'This must be a type of log defined in logs.json'),
                                   required=True)

    @classmethod
    def handler(cls, options, config):
        """Main Athena handler

        Args:
            options (argparse.Namespace): The parsed args passed from the CLI
            config (CLIConfig): Loaded StreamAlert config

        Returns:
            bool: False if errors occurred, True otherwise
        """
        if options.subcommand == 'rebuild-partitions':
            return rebuild_partitions(options.table_name, options.bucket, config)

        if options.subcommand == 'drop-all-tables':
            return drop_all_tables(config)

        if options.subcommand == 'create-table':
            return create_table(options.table_name, options.bucket, config, options.schema_override)


def get_athena_client(config):
    """Get an athena client using the current config settings

    Args:
        config (CLIConfig): Loaded StreamAlert config

    Returns:
        AthenaClient: instantiated client for performing athena actions
    """
    prefix = config['global']['account']['prefix']
    athena_config = config['lambda']['athena_partitioner_config']

    db_name = get_database_name(config)

    # Get the S3 bucket to store Athena query results
    results_bucket = athena_config.get('results_bucket',
                                       f's3://{prefix}-streamalert-athena-results')

    return AthenaClient(db_name,
                        results_bucket,
                        'streamalert_cli',
                        region=config['global']['account']['region'])


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
        config (CLIConfig): Loaded StreamAlert config

    Returns:
        bool: False if errors occurred, True otherwise
    """
    sanitized_table_name = FirehoseClient.sanitized_value(table)

    athena_client = get_athena_client(config)

    # Get the current set of partitions
    partitions = athena_client.get_table_partitions(sanitized_table_name)
    if not partitions:
        LOGGER.info('No partitions to rebuild for %s, nothing to do', sanitized_table_name)
        return False

    # Drop the table
    LOGGER.info('Dropping table %s', sanitized_table_name)
    if not athena_client.drop_table(sanitized_table_name):
        return False

    LOGGER.info('Creating table %s', sanitized_table_name)

    # Re-create the table with previous partitions
    if not create_table(table, bucket, config):
        return False

    new_partitions_statements = helpers.add_partition_statements(partitions, bucket,
                                                                 sanitized_table_name)

    LOGGER.info('Creating total %d new partitions for %s', len(partitions), sanitized_table_name)

    for idx, statement in enumerate(new_partitions_statements):
        success = athena_client.run_query(query=statement)
        LOGGER.info('Rebuilt partitions part %d', idx + 1)
        if not success:
            LOGGER.error('Error re-creating new partitions for %s', sanitized_table_name)
            write_partitions_statements(new_partitions_statements, sanitized_table_name)
            return False

    LOGGER.info('Successfully rebuilt all partitions for %s', sanitized_table_name)
    return True


def write_partitions_statements(statements, sanitized_table_name):
    """Write partitions statements to a file if re-creating new partitions failed"""
    file_name = f'partitions_{sanitized_table_name}.txt'
    LOGGER.error('Rebuild partitions failed, writing to local file with name %s', file_name)
    with open(file_name, 'w', encoding="utf-8") as partition_file:
        partition_file.write(statements)


def drop_all_tables(config):
    """Drop all 'streamalert' Athena tables

    Used when cleaning up an existing deployment

    Args:
        config (CLIConfig): Loaded StreamAlert config

    Returns:
        bool: False if errors occurred, True otherwise
    """
    if not continue_prompt(message='Are you sure you want to drop all Athena tables?'):
        return False

    athena_client = get_athena_client(config)

    if not athena_client.drop_all_tables():
        LOGGER.error('Failed to drop one or more tables from database: %s', athena_client.database)
        return False

    LOGGER.info('Successfully dropped all tables from database: %s', athena_client.database)
    return True


def _construct_create_table_statement(schema, table_name, bucket, file_format='parquet'):
    """Convert a dictionary based Athena schema to a Hive DDL statement

    Args:
        schema (dict): The sanitized Athena schema
        table_name (str): The name of the Athena table to create
        bucket (str): The S3 bucket containing the data

    Returns:
        str: The Hive DDL CREATE TABLE expression
    """
    # Construct the main Athena Schema
    schema_statement = []
    for key_name in sorted(schema.keys()):
        key_type = schema[key_name]
        if isinstance(key_type, str):
            schema_statement.append(f'{key_name} {key_type}')
        # Account for nested structs
        elif isinstance(key_type, dict):
            struct_schema = ', '.join(f'{sub_key}:{key_type[sub_key]}'
                                      for sub_key in sorted(key_type.keys()))
            schema_statement.append(f'{key_name} struct<{struct_schema}>')

    return CREATE_TABLE_STATEMENT.format(
        table_name=table_name,
        schema=', '.join(schema_statement),
        file_format=STORE_FORMAT_PARQUET if file_format == 'parquet' else STORE_FORMAT_JSON,
        bucket=bucket)


def create_table(table, bucket, config, schema_override=None):
    """Create a 'streamalert' Athena table

    Args:
        table (str): The name of the table being rebuilt
        bucket (str): The s3 bucket to be used as the location for Athena data
        table_type (str): The type of table being refreshed
        config (CLIConfig): Loaded StreamAlert config
        schema_override (set): An optional set of key=value pairs to be used for
            overriding the configured column_name=value_type.

    Returns:
        bool: False if errors occurred, True otherwise
    """
    enabled_logs = FirehoseClient.load_enabled_log_sources(
        config['global']['infrastructure']['firehose'], config['logs'])

    # Convert special characters in schema name to underscores
    sanitized_table_name = FirehoseClient.sanitized_value(table)

    # Check that the log type is enabled via Firehose
    if sanitized_table_name != 'alerts' and sanitized_table_name not in enabled_logs:
        LOGGER.error('Table name %s missing from configuration or '
                     'is not enabled.', sanitized_table_name)
        return False

    athena_client = get_athena_client(config)

    # Check if the table exists
    if athena_client.check_table_exists(sanitized_table_name):
        LOGGER.info('The \'%s\' table already exists.', sanitized_table_name)
        return True

    if table == 'alerts':
        # get a fake alert so we can get the keys needed and their types
        alert = Alert('temp_rule_name', {}, {})
        output = alert.output_dict()
        schema = record_to_schema(output)
        athena_schema = helpers.logs_schema_to_athena_schema(schema)

        # Use the bucket if supplied, otherwise use the default alerts bucket
        bucket = bucket or firehose_alerts_bucket(config)

        query = _construct_create_table_statement(schema=athena_schema,
                                                  table_name=table,
                                                  bucket=bucket,
                                                  file_format=get_data_file_format(config))

    else:  # all other tables are log types

        config_data_bucket = firehose_data_bucket(config)
        if not config_data_bucket:
            LOGGER.warning('The \'firehose\' module is not enabled in global.json')
            return False

        # Use the bucket if supplied, otherwise use the default data bucket
        bucket = bucket or config_data_bucket

        log_info = config['logs'][enabled_logs.get(sanitized_table_name)]

        schema = dict(log_info['schema'])
        sanitized_schema = FirehoseClient.sanitize_keys(schema)

        athena_schema = helpers.logs_schema_to_athena_schema(sanitized_schema)

        if configuration_options := log_info.get('configuration'):
            if envelope_keys := configuration_options.get('envelope_keys'):
                sanitized_envelope_key_schema = FirehoseClient.sanitize_keys(envelope_keys)
                # Note: this key is wrapped in backticks to be Hive compliant
                athena_schema['`streamalert:envelope_keys`'] = helpers.logs_schema_to_athena_schema(
                    sanitized_envelope_key_schema)

        # Handle Schema overrides
        #   This is useful when an Athena schema needs to differ from the normal log schema
        if schema_override:
            for override in schema_override:
                column_name, column_type = override.split('=')
                # Columns are escaped to avoid Hive issues with special characters
                column_name = f'`{column_name}`'
                if column_name in athena_schema:
                    athena_schema[column_name] = column_type
                    LOGGER.info('Applied schema override: %s:%s', column_name, column_type)
                else:
                    LOGGER.error('Schema override column %s not found in Athena Schema, skipping',
                                 column_name)

        query = _construct_create_table_statement(schema=athena_schema,
                                                  table_name=sanitized_table_name,
                                                  bucket=bucket,
                                                  file_format=get_data_file_format(config))

    success = athena_client.run_query(query=query)
    if not success:
        LOGGER.error('The %s table could not be created', sanitized_table_name)
        return False

    # Update the CLI config
    if table != 'alerts' and bucket != config_data_bucket:
        # Only add buckets to the config if they are not one of the default/configured buckets
        # Ensure 'buckets' exists in the config (since it is not required)
        config['lambda']['athena_partitioner_config']['buckets'] = (
            config['lambda']['athena_partitioner_config'].get('buckets', {}))
        if bucket not in config['lambda']['athena_partitioner_config']['buckets']:
            config['lambda']['athena_partitioner_config']['buckets'][bucket] = 'data'
            config.write()

    LOGGER.info('The %s table was successfully created!', sanitized_table_name)

    return True


def create_log_tables(config):
    """Create all tables needed for historical search
    Args:
        config (CLIConfig): Loaded StreamAlert config
    Returns:
        bool: False if errors occurred, True otherwise
    """
    if not config['global']['infrastructure'].get('firehose', {}).get('enabled'):
        return True

    firehose_config = config['global']['infrastructure']['firehose']
    firehose_s3_bucket_suffix = firehose_config.get('s3_bucket_suffix', 'streamalert-data')
    firehose_s3_bucket_name = f"{config['global']['account']['prefix']}-{firehose_s3_bucket_suffix}"

    enabled_logs = FirehoseClient.load_enabled_log_sources(
        config['global']['infrastructure']['firehose'], config['logs'])

    return all(
        create_table(log_stream_name, firehose_s3_bucket_name, config)
        for log_stream_name in enabled_logs)

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
from stream_alert.shared.logger import get_logger
from stream_alert.shared.lookup_tables.core import LookupTables
from stream_alert_cli.utils import CliCommand, generate_subparser

LOGGER = get_logger(__name__)


class LookupTablesCommand(CliCommand):

    description = 'Describe and manage your LookupTables'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add subparser for LookupTables"""
        lookup_tables_subparsers = subparser.add_subparsers()

        cls._setup_describe_tables_subparser(lookup_tables_subparsers)
        cls._setup_get_subparser(lookup_tables_subparsers)
        cls._setup_set_subparser(lookup_tables_subparsers)

    @classmethod
    def _setup_describe_tables_subparser(cls, subparsers):
        generate_subparser(
            subparsers,
            'describe-tables',
            description='Show tables',
            subcommand=True
        )

    @classmethod
    def _setup_get_subparser(cls, subparsers):
        """
        Get subcommand:

        $ ./manage.py lookup-tables get -t [table] -k [key]
        """
        get_parser = generate_subparser(
            subparsers,
            'get',
            description='Validate defined log schemas using integration test files',
            subcommand=True
        )

        get_parser.add_argument(
            '-t',
            '--table',
            help='Name of the LookupTable',
            required=True,
            default=None
        )

        get_parser.add_argument(
            '-k',
            '--key',
            help='Key to fetch on the LookupTable',
            required=True,
            default=None
        )

    @classmethod
    def _setup_set_subparser(cls, subparsers):
        """
        Set subcommand:

        $ ./manage.py lookup-tables set -t [table] -k [key] -v [value]
        """
        set_parser = generate_subparser(
            subparsers,
            'set',
            description='Validate defined log schemas using integration test files',
            subcommand=True
        )

        set_parser.add_argument(
            '-t',
            '--table',
            help='Name of the LookupTable',
            required=True,
            default=None
        )

        set_parser.add_argument(
            '-k',
            '--key',
            help='Key to set on the LookupTable',
            required=True,
            default=None
        )

        set_parser.add_argument(
            '-v',
            '--value',
            help='Value to save into LookupTable',
            required=True,
            default=None
        )

    @classmethod
    def handler(cls, options, config):
        subcommand = options.subcommand
        if subcommand == 'describe-tables':
            return cls._describe_tables_handler(config)

        if subcommand == 'get':
            return cls._get_handler(options, config)

        if subcommand == 'set':
            return cls._set_handler(options, config)

        LOGGER.error('Unhandled lookup-tables subcommand %s', subcommand)

    # pylint: disable=protected-access
    @staticmethod
    def _describe_tables_handler(config):
        LOGGER.info('==== LookupTables; Describe Tables ====\n')

        lookup_tables = LookupTables.get_instance(config=config)

        LOGGER.info('%d Tables:\n', len(lookup_tables._tables))
        for _, table in lookup_tables._tables.iteritems():
            LOGGER.info(' Table Name: %s', table.table_name)
            LOGGER.info(' Driver Id: %s', table.driver_id)
            LOGGER.info(' Driver Type: %s\n', table.driver_type)

    @staticmethod
    def _get_handler(options, config):
        """


        """

        table_name = options.table
        key = options.key

        LOGGER.info('==== LookupTables; Get Key ====')

        LookupTables.get_instance(config=config)

        LOGGER.info('  Table: %s', table_name)
        LOGGER.info('  Key:   %s', key)

        value = LookupTables.get(table_name, key)

        LOGGER.info('  Value: %s', value)

        return True

    @staticmethod
    def _set_handler(options, config):
        """

        """
        table_name = options.table
        key = options.key
        new_value = options.value

        LOGGER.info('==== LookupTables; Set Key ====')

        core = LookupTables.get_instance(config=config)

        LOGGER.info('  Table: %s', table_name)
        LOGGER.info('  Key:   %s', key)

        table = core.table(table_name)
        old_value = table.get(key)

        LOGGER.info('  Value: %s --> %s', old_value, new_value)

        table._driver.set(key, new_value)
        table._driver.commit()

        return True

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
import json

from stream_alert.shared.logger import get_logger
from stream_alert.shared.lookup_tables.core import LookupTables
from stream_alert.shared.lookup_tables.drivers import PersistenceDriver
from stream_alert_cli.utils import CLICommand, generate_subparser, set_parser_epilog

LOGGER = get_logger(__name__)


class LookupTablesCommand(CLICommand):

    description = 'Describe and manage your LookupTables'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add subparser for LookupTables"""
        set_parser_epilog(
            subparser,
            epilog=(
                '''\
                Examples:

                    manage.py lookup-tables [describe-tables|get|set]
                '''
            )
        )

        lookup_tables_subparsers = subparser.add_subparsers()

        cls._setup_describe_tables_subparser(lookup_tables_subparsers)
        cls._setup_get_subparser(lookup_tables_subparsers)
        cls._setup_set_subparser(lookup_tables_subparsers)

    @classmethod
    def _setup_describe_tables_subparser(cls, subparsers):
        describe_tables_parser = generate_subparser(
            subparsers,
            'describe-tables',
            description='Shows metadata about all currently configured LookupTables',
            subcommand=True
        )

        set_parser_epilog(
            describe_tables_parser,
            epilog=(
                '''\
                Examples:

                    manage.py lookup-tables describe-tables
                '''
            )
        )

    @classmethod
    def _setup_get_subparser(cls, subparsers):
        get_parser = generate_subparser(
            subparsers,
            'get',
            description='Retrieves a key from the requested LookupTable',
            subcommand=True
        )

        set_parser_epilog(
            get_parser,
            epilog=(
                '''\
                Examples:

                    manage.py lookup-tables get -t [table] -k [key]
                '''
            )
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
        set_parser = generate_subparser(
            subparsers,
            'set',
            description='Sets a key on the requested LookupTable',
            subcommand=True
        )

        set_parser_epilog(
            set_parser,
            epilog=(
                '''\
                Examples:

                    manage.py lookup-tables set -t [table] -k [key] -v [value] -j
                '''
            )
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

        set_parser.add_argument(
            '-j',
            '--json',
            help='Parse the given value as JSON instead of as a string',
            required=False,
            action='store_true'
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
        print('==== LookupTables; Describe Tables ====\n')

        lookup_tables = LookupTables.get_instance(config=config)

        print('{} Tables:\n'.format(len(lookup_tables._tables)))
        for _, table in lookup_tables._tables.items():
            print(' Table Name: {}'.format(table.table_name))
            print(' Driver Id: {}'.format(table.driver_id))
            print(' Driver Type: {}\n'.format(table.driver_type))

    @staticmethod
    def _get_handler(options, config):
        table_name = options.table
        key = options.key

        print('==== LookupTables; Get Key ====')

        LookupTables.get_instance(config=config)

        print('  Table: {}'.format(table_name))
        print('  Key:   {}'.format(key))

        value = LookupTables.get(table_name, key)

        print('  Value: {}'.format(value))
        print('  Type:  {}'.format(type(value)))

        return True

    @staticmethod
    def _set_handler(options, config):
        print('==== LookupTables; Set Key ====')

        table_name = options.table
        key = options.key

        if options.json:
            try:
                new_value = json.loads(options.value)
            except json.decoder.JSONDecodeError as e:
                print('  ERROR: Input is not valid JSON:')
                print(e)
                return False
        else:
            new_value = options.value

        core = LookupTables.get_instance(config=config)

        print('  Table: {}'.format(table_name))
        print('  Key:   {}'.format(key))

        table = core.table(table_name)

        if table.driver_type == PersistenceDriver.TYPE_NULL:
            print('  ERROR: Nonexistent table referenced!')
            return False

        old_value = table.get(key)

        print('  Value: {} --> {}'.format(old_value, new_value))

        table._driver.set(key, new_value)
        table._driver.commit()

        return True

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
import copy
import json

from stream_alert.shared.logger import get_logger
from stream_alert.shared.lookup_tables.core import LookupTables
from stream_alert_cli.utils import CLICommand, generate_subparser, set_parser_epilog

LOGGER = get_logger(__name__)


class LookupTablesCommand(CLICommand):
    description = 'Describe and manage your LookupTables'

    @classmethod
    def setup_subparser(cls, subparser):
        # FIXME (derek.wang) Refactor this into a more robust command-nesting framework
        subcommands = cls._subcommands()
        set_parser_epilog(
            subparser,
            epilog=(
                '''\
Available Sub-Commands:

{}

Examples:

    manage.py lookup-tables [describe-tables|get|set]
'''.format('\n'.join([
                    '\t{command: <{pad}}{description}'.format(
                        command=command,
                        pad=30,
                        description=subcommand.description
                    )
                    for command, subcommand
                    in subcommands.items()
                ]))
            )
        )

        lookup_tables_subparsers = subparser.add_subparsers()

        for subcommand in subcommands.values():
            subcommand.setup_subparser(lookup_tables_subparsers)

    @classmethod
    def handler(cls, options, config):
        subcommands = cls._subcommands()
        if options.subcommand in subcommands:
            return subcommands[options.subcommand].handler(options, config)

        LOGGER.error('Unhandled lookup-tables subcommand %s', options.subcommand)

    @classmethod
    def _subcommands(cls):
        return {
            # FIXME (derek.wang) Put the command strings into the commands themselves, so the
            #   subparsers can be registered easily
            'describe-tables': LookupTablesDescribeTablesSubCommand,
            'get': LookupTablesGetKeySubCommand,
            'set': LookupTablesSetSubCommand,
            'list-add': LookupTablesListAddSubCommand,
        }


class LookupTablesListAddSubCommand(CLICommand):
    description = 'Add a value to a list-typed LookupTables key'

    @classmethod
    def setup_subparser(cls, subparser):
        set_parser = generate_subparser(
            subparser,
            'list-add',
            description='Sets a key on the requested LookupTable',
            subcommand=True
        )

        set_parser_epilog(
            set_parser,
            epilog=(
                '''\
                Examples:

                    manage.py lookup-tables list-add -t [table] -k [key] -v [value]
                '''
            )
        )

        set_parser.add_argument(
            '-t',
            '--table',
            help='Name of the LookupTable',
            required=True
        )

        set_parser.add_argument(
            '-k',
            '--key',
            help='Key to modify on the LookupTable',
            required=True
        )

        set_parser.add_argument(
            '-v',
            '--value',
            help='Value to add to the key',
            required=True
        )

    # pylint: disable=protected-access
    @classmethod
    def handler(cls, options, config):
        print('==== LookupTables; List Add Key ====')

        table_name = options.table
        key = options.key

        core = LookupTables.get_instance(config=config)

        print('  Table: {}'.format(table_name))
        print('  Key:   {}'.format(key))

        table = core.table(table_name)
        old_value = table.get(key)

        if old_value is None:
            old_value = []

        if not isinstance(old_value, list):
            print('  ERROR: The current value is not a list: {}'.format(old_value))
            return False

        new_value = copy.copy(old_value)
        new_value.append(options.value)
        sorted(new_value)

        print('  Value: {} --> {}'.format(old_value, new_value))

        table._driver.set(key, new_value)
        table._driver.commit()

        return True


class LookupTablesDescribeTablesSubCommand(CLICommand):
    description = 'Show information about all currently configured LookupTables'

    @classmethod
    def setup_subparser(cls, subparser):
        describe_tables_parser = generate_subparser(
            subparser,
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

    # pylint: disable=protected-access
    @classmethod
    def handler(cls, options, config):
        print('==== LookupTables; Describe Tables ====\n')

        lookup_tables = LookupTables.get_instance(config=config)

        print('{} Tables:\n'.format(len(lookup_tables._tables)))
        for table in lookup_tables._tables.values():
            print(' Table Name: {}'.format(table.table_name))
            print(' Driver Id: {}'.format(table.driver_id))
            print(' Driver Type: {}\n'.format(table.driver_type))


class LookupTablesGetKeySubCommand(CLICommand):
    description = 'Retrieve a key from an existing LookupTable'

    @classmethod
    def setup_subparser(cls, subparser):
        get_parser = generate_subparser(
            subparser,
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
            required=True
        )

        get_parser.add_argument(
            '-k',
            '--key',
            help='Key to fetch on the LookupTable',
            required=True
        )

    @classmethod
    def handler(cls, options, config):
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


class LookupTablesSetSubCommand(CLICommand):
    description = 'Update the key of an existing LookupTable'

    @classmethod
    def setup_subparser(cls, subparser):
        set_parser = generate_subparser(
            subparser,
            'set',
            description='Sets a key on the requested LookupTable',
            subcommand=True
        )

        set_parser_epilog(
            set_parser,
            epilog=(
                '''\
                Examples:

                    manage.py lookup-tables set -t [table] -k [key] -v [value]
                '''
            )
        )

        set_parser.add_argument(
            '-t',
            '--table',
            help='Name of the LookupTable',
            required=True
        )

        set_parser.add_argument(
            '-k',
            '--key',
            help='Key to set on the LookupTable',
            required=True
        )

        set_parser.add_argument(
            '-v',
            '--value',
            help='Value to save into LookupTable',
            required=True
        )

    # pylint: disable=protected-access
    @classmethod
    def handler(cls, options, config):
        print('==== LookupTables; Set Key ====')

        table_name = options.table
        key = options.key

        try:
            new_value = json.loads(options.value)
        except json.decoder.JSONDecodeError as e:
            print('  ERROR: Input is not valid JSON:')
            print(e)
            return False

        core = LookupTables.get_instance(config=config)

        print('  Table: {}'.format(table_name))
        print('  Key:   {}'.format(key))

        table = core.table(table_name)
        old_value = table.get(key)

        print('  Value: {} --> {}'.format(old_value, new_value))

        table._driver.set(key, new_value)
        table._driver.commit()

        return True

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
import copy
import json

from streamalert.shared.logger import get_logger
from streamalert.shared.lookup_tables.core import LookupTables
from streamalert.shared.lookup_tables.utils import LookupTablesMagic
from streamalert_cli.utils import (CLICommand, generate_subparser,
                                   set_parser_epilog)

LOGGER = get_logger(__name__)


class LookupTablesCommand(CLICommand):
    description = 'Describe and manage your LookupTables'

    @classmethod
    def setup_subparser(cls, subparser):
        # FIXME (derek.wang) Refactor this into a more robust command-nesting framework
        template = '''\
Available Sub-Commands:

{}

Examples:

    manage.py lookup-tables [describe-tables|get|set]
'''
        subcommands = cls._subcommands()
        set_parser_epilog(
            subparser,
            epilog=(
                template.format('\n'.join([
                    '\t{command: <{pad}}{description}'.format(
                        command=command,
                        pad=30,

                        # FIXME (Derek.wang)
                        #   Ryan suggested that we could implement a __str__ or __repr__ function
                        #   for each of the CLICommand classes
                        description=subcommand.description)
                    for command, subcommand in subcommands.items()
                ]))))

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
            'set-from-json-file': LookupTablesSetFromFile,
        }


class LookupTablesSetFromFile(CLICommand):
    description = 'Set a LookupTable key from a JSON file'

    @classmethod
    def setup_subparser(cls, subparser):
        set_parser = generate_subparser(
            subparser,
            'set-from-json-file',
            description='Pushes the contents of a given json file into the LookupTable key',
            subcommand=True)

        set_parser_epilog(set_parser,
                          epilog=('''\
                Examples:

                    manage.py lookup-tables set-from-json-file -t [table] -k [key] -f \
[path/to/file.json]
                '''))

        set_parser.add_argument('-t', '--table', help='Name of the LookupTable', required=True)

        set_parser.add_argument('-k',
                                '--key',
                                help='Key to modify on the LookupTable',
                                required=True)

        set_parser.add_argument(
            '-f',
            '--file',
            help='Path to the json file, relative to the current working directory',
            required=True)

    @classmethod
    def handler(cls, options, config):
        print('==== LookupTables; Set from JSON File ====')

        core = LookupTables.get_instance(config=config)

        print(f'  Table: {options.table}')
        print(f'  Key:   {options.key}')
        print(f'  File:  {options.file}')

        table = core.table(options.table)

        old_value = table.get(options.key)

        with open(options.file, encoding="utf-8") as json_file_fp:
            new_value = json.load(json_file_fp)

        print('  Value: {} --> {}'.format(json.dumps(old_value, indent=2, sort_keys=True),
                                          json.dumps(new_value, indent=2, sort_keys=True)))

        LookupTablesMagic.set_table_value(table, options.key, new_value)

        return True


class LookupTablesListAddSubCommand(CLICommand):
    description = 'Add a value to a list-typed LookupTables key'

    @classmethod
    def setup_subparser(cls, subparser):
        set_parser = generate_subparser(subparser,
                                        'list-add',
                                        description='Sets a key on the requested LookupTable',
                                        subcommand=True)

        set_parser_epilog(set_parser,
                          epilog=('''\
                Examples:

                    manage.py lookup-tables list-add -t [table] -k [key] -v [value]
                '''))

        set_parser.add_argument('-t', '--table', help='Name of the LookupTable', required=True)

        set_parser.add_argument('-k',
                                '--key',
                                help='Key to modify on the LookupTable',
                                required=True)

        set_parser.add_argument('-v', '--value', help='Value to add to the key', required=True)

        set_parser.add_argument('-u',
                                '--unique',
                                help='Remove duplicate values from the final list',
                                action='store_true')

        set_parser.add_argument('-s', '--sort', help='Sort the final list', action='store_true')

    @classmethod
    def handler(cls, options, config):
        print('==== LookupTables; List Add Key ====')

        table_name = options.table
        key = options.key

        core = LookupTables.get_instance(config=config)

        print(f'  Table: {table_name}')
        print(f'  Key:   {key}')

        table = core.table(table_name)
        old_value = table.get(key)

        if old_value is None:
            old_value = []

        if not isinstance(old_value, list):
            print(f'  ERROR: The current value is not a list: {old_value}')
            return False

        new_value = copy.copy(old_value)
        new_value.append(options.value)

        if options.unique:
            new_value = list(set(new_value))

        if options.sort:
            new_value = sorted(new_value)

        print(f'  Value: {old_value} --> {new_value}')

        LookupTablesMagic.set_table_value(table, key, new_value)

        return True


class LookupTablesDescribeTablesSubCommand(CLICommand):
    description = 'Show information about all currently configured LookupTables'

    @classmethod
    def setup_subparser(cls, subparser):
        describe_tables_parser = generate_subparser(
            subparser,
            'describe-tables',
            description='Shows metadata about all currently configured LookupTables',
            subcommand=True)

        set_parser_epilog(describe_tables_parser,
                          epilog=('''\
                Examples:

                    manage.py lookup-tables describe-tables
                '''))

    @classmethod
    def handler(cls, options, config):
        print('==== LookupTables; Describe Tables ====\n')

        lookup_tables = LookupTablesMagic.get_all_tables(LookupTables.get_instance(config=config))

        print(f'{len(lookup_tables)} Tables:\n')
        for table in lookup_tables.values():
            print(f' Table Name: {table.table_name}')
            print(f' Driver Id: {table.driver_id}')
            print(f' Driver Type: {table.driver_type}\n')


class LookupTablesGetKeySubCommand(CLICommand):
    description = 'Retrieve a key from an existing LookupTable'

    @classmethod
    def setup_subparser(cls, subparser):
        get_parser = generate_subparser(
            subparser,
            'get',
            description='Retrieves a key from the requested LookupTable',
            subcommand=True)

        set_parser_epilog(get_parser,
                          epilog=('''\
                Examples:

                    manage.py lookup-tables get -t [table] -k [key]
                '''))

        get_parser.add_argument('-t', '--table', help='Name of the LookupTable', required=True)

        get_parser.add_argument('-k',
                                '--key',
                                help='Key to fetch on the LookupTable',
                                required=True)

    @classmethod
    def handler(cls, options, config):
        table_name = options.table
        key = options.key

        print('==== LookupTables; Get Key ====')

        LookupTables.get_instance(config=config)

        print(f'  Table: {table_name}')
        print(f'  Key:   {key}')

        value = LookupTables.get(table_name, key)

        print()
        print(f'  Type:  {type(value)}')

        if isinstance(value, (list, dict)):
            # Render lists and dicts a bit better to make them easier to read
            print('  Value:')
            print(json.dumps(value, indent=2, sort_keys=True))
        else:
            print(f'  Value: {value}')

        print()

        return True


class LookupTablesSetSubCommand(CLICommand):
    description = 'Update the key of an existing LookupTable'

    @classmethod
    def setup_subparser(cls, subparser):
        set_parser = generate_subparser(subparser,
                                        'set',
                                        description='Sets a key on the requested LookupTable',
                                        subcommand=True)

        set_parser_epilog(set_parser,
                          epilog=('''\
                Examples:

                    manage.py lookup-tables set -t [table] -k [key] -v [value]
                '''))

        set_parser.add_argument('-t', '--table', help='Name of the LookupTable', required=True)

        set_parser.add_argument('-k', '--key', help='Key to set on the LookupTable', required=True)

        set_parser.add_argument('-v',
                                '--value',
                                help='Value to save into LookupTable',
                                required=True)

        set_parser.add_argument('-j',
                                '--json',
                                help='Interpret the value as a JSON-encoded string',
                                action='store_true')

    @classmethod
    def handler(cls, options, config):
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

        print(f'  Table: {table_name}')
        print(f'  Key:   {key}')

        table = core.table(table_name)
        old_value = table.get(key)

        print(f'  Value: {old_value} --> {new_value}')

        LookupTablesMagic.set_table_value(table, key, new_value)

        return True

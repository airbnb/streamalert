#! /usr/bin/env python
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

---------------------------------------------------------------------------

This script builds StreamAlert AWS infrastructure, is responsible for
deploying to AWS Lambda, and publishing production versions.

To run terraform by hand, change to the terraform directory and run:

terraform <cmd>
"""
import sys
from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter

from streamalert import __version__ as version
from streamalert_cli.config import DEFAULT_CONFIG_PATH
from streamalert_cli.runner import StreamAlertCLICommandRepository, cli_runner
from streamalert_cli.utils import (DirectoryType,
                                   UniqueSortedFileListAppendAction,
                                   generate_subparser)


def build_parser():
    """Build the argument parser."""

    # Map of top-level commands and their setup functions/description
    # New top-level commands should be added to this dictionary
    commands = StreamAlertCLICommandRepository.command_parsers()

    description_template = """
StreamAlert v{}

Configure, test, build, and deploy StreamAlert

Available Commands:

{}

For additional help with any command above, try:

        {} [command] --help
"""
    parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter, prog=__file__)

    parser.add_argument('-v', '--version', action='version', version=version)

    parser.add_argument('-d',
                        '--debug',
                        help='enable debugging logger output for all of the StreamAlert loggers',
                        action='store_true')

    parser.add_argument('-c',
                        '--config-dir',
                        default=DEFAULT_CONFIG_PATH,
                        help='Path to directory containing configuration files',
                        type=DirectoryType())

    parser.add_argument('-t',
                        '--terraform-file',
                        dest='terraform_files',
                        help=('Path to one or more additional Terraform configuration '
                              'files to include in this deployment'),
                        action=UniqueSortedFileListAppendAction,
                        type=FileType('r'),
                        default=[])

    parser.add_argument(
        '-b',
        '--build-directory',
        help=('Path to directory to use for building StreamAlert and its infrastructure. '
              'If no path is provided, a temporary directory will be used.'),
        type=str)

    # Dynamically generate subparsers, and create a 'commands' block for the prog description
    command_block = []
    subparsers = parser.add_subparsers(dest='command', required=True)
    command_col_size = max(len(command) for command in commands) + 10
    for command in sorted(commands):
        setup_subparser_func, description = commands[command]
        subparser = generate_subparser(subparsers, command, description=description)

        # If there are additional arguments to set for this command, call its setup function
        if setup_subparser_func:
            setup_subparser_func(subparser)

        command_block.append('\t{command: <{pad}}{description}'.format(command=command,
                                                                       pad=command_col_size,
                                                                       description=description))

    # Update the description on the top level parser
    parser.description = description_template.format(version, '\n'.join(command_block), __file__)

    parser.epilog = 'Issues? Please report here: https://github.com/airbnb/streamalert/issues'

    return parser


def main():
    """Entry point for the CLI."""
    parser = build_parser()
    options = parser.parse_args()

    # Exit with the result, which will be False if an error occurs, or True otherwise
    return not cli_runner(options)


if __name__ == "__main__":
    sys.exit(main())

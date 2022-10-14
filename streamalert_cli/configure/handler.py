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
from streamalert_cli.utils import CLICommand, set_parser_epilog


class ConfigureCommand(CLICommand):
    description = 'Configure global StreamAlert settings'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add configure subparser: manage.py configure key value"""
        set_parser_epilog(subparser,
                          epilog=('''\
                Example:

                    manage.py configure prefix orgname
                '''))

        subparser.add_argument('key',
                               choices=['prefix', 'aws_account_id'],
                               help='Value of key being configured')

        subparser.add_argument('value', help='Value to assign to key being configured')

    @classmethod
    def handler(cls, options, config):
        """Configure StreamAlert main settings

            Args:
                options (argparse.Namespace): ArgParse command result

            Returns:
                bool: False if errors occurred, True otherwise
            """
        if options.key == 'prefix':
            return config.set_prefix(options.value)

        if options.key == 'aws_account_id':
            return config.set_aws_account_id(options.value)

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


class ThreatIntelCommand(CLICommand):
    description = 'Enable/disable and configure the StreamAlert Threat Intelligence feature'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add threat intel subparser: manage.py threat-intel [action]"""
        set_parser_epilog(subparser,
                          epilog=('''\
                Examples:

                    manage.py threat-intel \\
                      enable \\
                      --dynamodb-table my_ioc_table
                '''))

        actions = ['disable', 'enable']
        subparser.add_argument(
            'action',
            metavar='ACTION',
            choices=actions,
            help=f"One of the following actions to be performed: {', '.join(actions)}")

        subparser.add_argument('--dynamodb-table',
                               dest='dynamodb_table_name',
                               help='DynamoDB table name where IOC information is stored')

    @classmethod
    def handler(cls, options, config):
        """Configure Threat Intel from command line

        Args:
            options (argparse.Namespace): The parsed args passed from the CLI
            config (CLIConfig): Loaded StreamAlert config

        Returns:
            bool: False if errors occurred, True otherwise
        """
        config.add_threat_intel(vars(options))
        return True

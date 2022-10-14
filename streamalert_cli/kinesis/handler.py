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
from streamalert.shared.logger import get_logger
from streamalert_cli.terraform.generate import terraform_generate_handler
from streamalert_cli.terraform.helpers import terraform_runner
from streamalert_cli.utils import (CLICommand, add_clusters_arg,
                                   set_parser_epilog)

LOGGER = get_logger(__name__)


class KinesisCommand(CLICommand):
    description = 'Update AWS Kinesis settings and run Terraform to apply changes'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add kinesis subparser: manage.py kinesis [options]"""
        set_parser_epilog(subparser,
                          epilog=('''\
                Example:

                    manage.py kinesis disable-events --clusters corp prod
                '''))

        actions = ['disable-events', 'enable-events']
        subparser.add_argument(
            'action',
            metavar='ACTION',
            choices=actions,
            help=f"One of the following actions to be performed: {', '.join(actions)}")

        # Add the option to specify cluster(s)
        add_clusters_arg(subparser)

        subparser.add_argument('-s',
                               '--skip-terraform',
                               action='store_true',
                               help='Only update the config options and do not run Terraform')

    @classmethod
    def handler(cls, options, config):
        """Main handler for the Kinesis parser

        Args:
            options (argparse.Namespace): Parsed arguments
            config (CLIConfig): Loaded StreamAlert config

        Returns:
            bool: False if errors occurred, True otherwise
        """
        enable = options.action == 'enable-events'
        LOGGER.info('%s Kinesis Events', 'Enabling' if enable else 'Disabling')

        for cluster in options.clusters or config.clusters():
            if 'kinesis_events' in config['clusters'][cluster]['modules']:
                config['clusters'][cluster]['modules']['kinesis_events']['enabled'] = enable

        config.write()

        if options.skip_terraform:
            return True  # not an error

        return terraform_runner(
            config, targets=[f'module.kinesis_events_{cluster}' for cluster in config.clusters()
                             ]) if terraform_generate_handler(config) else False

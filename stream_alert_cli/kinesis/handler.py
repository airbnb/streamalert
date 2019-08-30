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
from stream_alert_cli.helpers import tf_runner
from stream_alert_cli.terraform.generate import terraform_generate_handler
from stream_alert_cli.utils import CliCommand, set_parser_epilog, add_clusters_arg

LOGGER = get_logger(__name__)


class KinesisCommand(CliCommand):
    description = 'Update AWS Kinesis settings and run Terraform to apply changes'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add kinesis subparser: manage.py kinesis [options]"""
        set_parser_epilog(
            subparser,
            epilog=(
                '''\
                Example:

                    manage.py kinesis disable-events --clusters corp prod
                '''
            )
        )

        actions = ['disable-events', 'enable-events']
        subparser.add_argument(
            'action',
            metavar='ACTION',
            choices=actions,
            help='One of the following actions to be performed: {}'.format(', '.join(actions))
        )

        # Add the option to specify cluster(s)
        add_clusters_arg(subparser)

        subparser.add_argument(
            '-s',
            '--skip-terraform',
            action='store_true',
            help='Only update the config options and do not run Terraform'
        )

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

        if not terraform_generate_handler(config):
            return False

        return tf_runner(
            action='apply',
            targets=[
                'module.{}_{}'.format('kinesis_events', cluster) for cluster in config.clusters()
            ]
        )

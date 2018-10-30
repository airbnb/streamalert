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

LOGGER = get_logger(__name__)


def kinesis_handler(options, config):
    """Main handler for the Kinesis parser

    Args:
        options (namedtuple): Parsed arguments
        config (CLIConfig): Loaded StreamAlert config
    """
    enable = options.action == 'enable-events'
    LOGGER.info('%s Kinesis Events', 'Enabling' if enable else 'Disabling')

    for cluster in options.clusters or config.clusters():
        if 'kinesis_events' in config['clusters'][cluster]['modules']:
            config['clusters'][cluster]['modules']['kinesis_events']['enabled'] = enable

    config.write()

    if options.skip_terraform:
        return

    terraform_generate_handler(config)
    tf_runner(
        action='apply',
        targets=[
            'module.{}_{}'.format('kinesis_events', cluster) for cluster in config.clusters()
        ]
    )

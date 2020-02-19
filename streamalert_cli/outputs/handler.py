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
from streamalert.shared.logger import get_logger
from streamalert.alert_processor.outputs.output_base import (
    StreamAlertOutput,
    OutputCredentialsProvider
)
from streamalert_cli.helpers import user_input
from streamalert_cli.outputs.helpers import output_exists
from streamalert_cli.utils import CLICommand

LOGGER = get_logger(__name__)


class OutputCommand(CLICommand):
    description = 'Create a new StreamAlert output'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the output subparser: manage.py output SERVICE"""
        outputs = sorted(StreamAlertOutput.get_all_outputs().keys())

        # Output parser arguments
        subparser.add_argument(
            'service',
            choices=outputs,
            metavar='SERVICE',
            help='Create a new StreamAlert output for one of the available services: {}'.format(
                ', '.join(outputs)
            )
        )

    @classmethod
    def handler(cls, options, config):
        """Configure a new output for this service

        Args:
            options (argparse.Namespace): Basically a namedtuple with the service setting

        Returns:
            bool: False if errors occurred, True otherwise
        """
        account_config = config['global']['account']
        region = account_config['region']
        prefix = account_config['prefix']
        kms_key_alias = account_config.get(
            'kms_key_alias',
            '{}_streamalert_secrets'.format(prefix)
        )
        # Verify that the word alias is not in the config.
        # It is interpolated when the API call is made.
        if 'alias/' in kms_key_alias:
            kms_key_alias = kms_key_alias.split('/')[1]

        # Retrieve the proper service class to handle dispatching the alerts of this services
        output = StreamAlertOutput.get_dispatcher(options.service)

        # If an output for this service has not been defined, the error is logged
        # prior to this
        if not output:
            return False

        # get dictionary of OutputProperty items to be used for user prompting
        props = output.get_user_defined_properties()

        for name, prop in props.items():
            # pylint: disable=protected-access
            props[name] = prop._replace(
                value=user_input(prop.description, prop.mask_input, prop.input_restrictions))

        output_config = config['outputs']
        service = output.__service__

        # If it exists already, ask for user input again for a unique configuration
        if output_exists(output_config, props, service):
            return cls.handler(options, config)

        provider = OutputCredentialsProvider(service, config=config, region=region, prefix=prefix)
        result = provider.save_credentials(props['descriptor'].value, kms_key_alias, props)
        if not result:
            LOGGER.error('An error occurred while saving \'%s\' '
                         'output configuration for service \'%s\'', props['descriptor'].value,
                         options.service)
            return False

        updated_config = output.format_output_config(output_config, props)
        output_config[service] = updated_config
        config.write()

        LOGGER.info('Successfully saved \'%s\' output configuration for service \'%s\'',
                    props['descriptor'].value, options.service)
        return True

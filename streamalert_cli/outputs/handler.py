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
import json

from streamalert.alert_processor.outputs.output_base import (
    OutputCredentialsProvider, StreamAlertOutput)
from streamalert.shared.logger import get_logger
from streamalert_cli.helpers import response_is_valid, user_input
from streamalert_cli.outputs.helpers import output_exists
from streamalert_cli.utils import CLICommand, generate_subparser

LOGGER = get_logger(__name__)
OUTPUTS_FILE = 'outputs_to_configure.json'


class OutputCommand(CLICommand):
    description = 'Describe and manage StreamAlert outputs'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the output subparser: manage.py output"""
        output_subparsers = subparser.add_subparsers()

        for subcommand in cls._subcommands().values():
            subcommand.setup_subparser(output_subparsers)

    @classmethod
    def handler(cls, options, config):
        subcommands = cls._subcommands()

        if options.subcommand in subcommands:
            return subcommands[options.subcommand].handler(options, config)

        LOGGER.error('Unhandled output subcommand %s', options.subcommand)

    @staticmethod
    def _subcommands():
        return {
            'set': OutputSetSubCommand,
            'set-from-file': OutputSetFromFileSubCommand,
            'generate-skeleton': OutputGenerateSkeletonSubCommand,
            'get': OutputGetSubCommand,
            'list': OutputListSubCommand
        }


class OutputSharedMethods:
    @staticmethod
    def save_credentials(service, config, properties):
        """Save credentials for the provided service

        Args:
            service (str): The name of the service the output belongs too
            config (StreamAlert.config): The configuration of StreamAlert
            properties (OrderedDict): Contains various OutputProperty items
        Returns:
            bool: False if errors occurred, True otherwise
        """
        account_config = config['global']['account']
        region = account_config['region']
        prefix = account_config['prefix']
        kms_key_alias = account_config.get('kms_key_alias', f'{prefix}_streamalert_secrets')

        # Verify that the word alias is not in the config.
        # It is interpolated when the API call is made.
        if 'alias/' in kms_key_alias:
            kms_key_alias = kms_key_alias.split('/')[1]

        provider = OutputCredentialsProvider(service, config=config, region=region, prefix=prefix)
        result = provider.save_credentials(properties['descriptor'].value, kms_key_alias,
                                           properties)
        if not result:
            LOGGER.error(
                'An error occurred while saving \'%s\' '
                'output configuration for service \'%s\'', properties['descriptor'].value, service)
        return result

    @staticmethod
    def update_config(options, config, properties, output, service):
        """Update the local config files

        Args:
            options (argparse.Namespace): Basically a namedtuple with the service setting
            config (StreamAlert.config): The configuration of StreamAlert
            properties (OrderedDict): Contains various OutputProperty items
            output (StreamAlert.OutputDispatcher): The output to update
            service (str): The name of the service the output belongs too
        """
        output_config = config['outputs']
        descriptor = properties['descriptor'].value

        if options.update and output_exists(output_config, properties, service, log_message=False):
            # Don't update the config if the output already existed, this will prevent duplicates
            LOGGER.debug(
                'Output already exists, don\'t update the config for descriptor %s and service %s',
                descriptor, service)
        else:
            updated_config = output.format_output_config(output_config, properties)
            output_config[service] = updated_config
            config.write()

            LOGGER.debug('Successfully saved \'%s\' output configuration for service \'%s\'',
                         descriptor, service)


class OutputSetSubCommand(CLICommand, OutputSharedMethods):
    description = 'Set a single output'

    @classmethod
    def setup_subparser(cls, subparser):
        """Setup: manage.py output set [options]

        Args:
            outputs (list): List of available output services
        """
        outputs = sorted(StreamAlertOutput.get_all_outputs().keys())

        set_parser = generate_subparser(subparser,
                                        'set',
                                        description=cls.description,
                                        help=cls.description,
                                        subcommand=True)

        # Add the required positional arg of service
        set_parser.add_argument(
            'service',
            choices=outputs,
            metavar='SERVICE',
            help=
            f"Create a new StreamAlert output for one of the available services: {', '.join(outputs)}"
        )

        # Add the optional update flag, which allows existing outputs to be updated
        set_parser.add_argument('--update',
                                '-u',
                                action='store_true',
                                default=False,
                                help='If the output already exists, overwrite it')

    @classmethod
    def handler(cls, options, config):
        """Configure a new output for this service
        Args:
            options (argparse.Namespace): Basically a namedtuple with the service setting
            config (StreamAlert.config): The configuration of StreamAlert
        Returns:
            bool: False if errors occurred, True otherwise
        """
        # Retrieve the proper service class to handle dispatching the alerts of this services
        output = StreamAlertOutput.get_dispatcher(options.service)

        # If an output for this service has not been defined, the error is logged
        # prior to this
        if not output:
            return False

        # get dictionary of OutputProperty items to be used for user prompting
        properties = output.get_user_defined_properties()

        for name, prop in properties.items():
            # pylint: disable=protected-access
            properties[name] = prop._replace(
                value=user_input(prop.description, prop.mask_input, prop.input_restrictions))

        service = output.__service__

        if not options.update and output_exists(config['outputs'], properties, service):
            # If the output already exists and update is not set
            # ask for user input again for a unique configuration
            return cls.handler(options, config)

        if not cls.save_credentials(service, config, properties):
            # Error message is already logged so no need to log a new one
            return False

        cls.update_config(options, config, properties, output, service)

        LOGGER.info('Successfully saved \'%s\' output configuration for service \'%s\'',
                    properties['descriptor'].value, service)
        return True


class OutputSetFromFileSubCommand(CLICommand, OutputSharedMethods):
    description = 'Set numerous outputs from a file'

    @classmethod
    def setup_subparser(cls, subparser):
        """Setup: manage.py output set-from-file [options]

        Args:
            outputs (list): List of available output services
        """
        set_from_file_parser = generate_subparser(subparser,
                                                  'set-from-file',
                                                  description=cls.description,
                                                  help=cls.description,
                                                  subcommand=True)

        # Add the optional file flag
        set_from_file_parser.add_argument(
            '--file',
            '-f',
            default=OUTPUTS_FILE,
            help='Path to the json file, relative to the current working directory')

        # Add the optional update flag, which allows existing outputs to be updated
        set_from_file_parser.add_argument('--update',
                                          '-u',
                                          action='store_true',
                                          default=False,
                                          help='Allow existing outputs to be overwritten')

    @classmethod
    def handler(cls, options, config):
        """Configure multiple outputs for multiple services
        Args:
            options (argparse.Namespace): Basically a namedtuple with the service setting
            config (StreamAlert.config): The configuration of StreamAlert
        Returns:
            bool: False if errors occurred, True otherwise
        """
        try:
            with open(options.file, encoding="utf-8") as json_file_fp:
                file_contents = json.load(json_file_fp)
        except Exception:  # pylint: disable=broad-except
            LOGGER.error("Error opening file %s", options.file)
            return False

        if not file_contents:
            LOGGER.error('File %s is empty', options.file)
            return False

        for service, configurations in file_contents.items():
            LOGGER.debug('Setting outputs for service %s', service)
            # Retrieve the proper service class to handle dispatching the alerts of this service
            output = StreamAlertOutput.get_dispatcher(service)

            for configuration in configurations:
                properties = cls.convert_configuration_to_properties(configuration, output)
                if not properties:
                    # Configuration was not valid
                    return False

                if not options.update and output_exists(config['outputs'], properties, service):
                    # If the output already exists and update is not set
                    # return early
                    return False

                # For each configuration for this service, save the creds and update the config
                if not cls.save_credentials(service, config, properties):
                    return False
                cls.update_config(options, config, properties, output, service)

            LOGGER.info('Saved %s configurations for service: %s', len(configurations), service)

        LOGGER.info('Finished setting all configurations for services: %s', file_contents.keys())
        return True

    @staticmethod
    def convert_configuration_to_properties(configuration, output):
        """Check the configuration meets all input_restrictions

        Args:
            configuration (dict): The configuration to check and convert to OutputProperties
            output (StreamAlert.OutputDispatcher): The output to map the configuration to
        Returns:
            OrderedDict: If the configuration is valid for the passed OutputDispatcher else None
        """
        properties = output.get_user_defined_properties()

        for name, value in configuration.items():
            if name not in properties:
                LOGGER.error('unknown key %s passed for service: %s', name, output.__service__)
                break

            prop = properties[name]
            if not response_is_valid(value, prop.input_restrictions):
                # Error messages are handled by response_is_valid
                break

            properties[name] = prop._replace(value=value)
        else:
            return properties


class OutputGenerateSkeletonSubCommand(CLICommand):
    description = 'Generate the skeleton file for use with set-from-file'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add generate-skeleton subparser to the output subparser"""
        outputs = sorted(StreamAlertOutput.get_all_outputs().keys())

        # Create the generate-skeleton parser
        generate_skeleton_parser = generate_subparser(subparser,
                                                      'generate-skeleton',
                                                      description=cls.description,
                                                      help=cls.description,
                                                      subcommand=True)

        # Add the optional ability to pass services
        generate_skeleton_parser.add_argument(
            '--services',
            choices=outputs,
            nargs='+',
            metavar='SERVICE',
            default=outputs,
            help=
            f"Pass the services to generate the skeleton for from services: {', '.join(outputs)}")

        # Add the optional file flag
        generate_skeleton_parser.add_argument(
            '--file',
            '-f',
            default=OUTPUTS_FILE,
            help='File to write to, relative to the current working directory')

    @classmethod
    def handler(cls, options, config):
        """Generate a skeleton file for use with set-from-file
        Args:
            options (argparse.Namespace): Basically a namedtuple with the service setting
            config (StreamAlert.config): The configuration of StreamAlert
        Returns:
            bool: False if errors occurred, True otherwise
        """

        skeleton = {}
        for service in options.services:
            # Retrieve the proper service class to handle dispatching the alerts of this services
            # No need to safeguard, as choices are defined on --services
            output = StreamAlertOutput.get_dispatcher(service)

            # get dictionary of OutputProperty items to be used for user prompting
            properties = output.get_user_defined_properties()
            skeleton[service] = [{
                name: f'desc: {prop.description}, restrictions: {prop.input_restrictions}'
                for name, prop in properties.items()
            }]

        try:
            with open(options.file, 'w', encoding="utf-8") as json_file_fp:
                json.dump(skeleton, json_file_fp, indent=2, sort_keys=True)
        except Exception as err:  # pylint: disable=broad-except
            LOGGER.error(err)
            return False

        LOGGER.info('Successfully generated the Skeleton file %s for services: %s', options.file,
                    options.services)
        return True


class OutputGetSubCommand(CLICommand):
    description = 'Get the existing configuration for outputs'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the output get subparser: manage.py output get [options]"""
        outputs = sorted(StreamAlertOutput.get_all_outputs().keys())

        get_parser = generate_subparser(
            subparser,
            'get',
            description=cls.description,
            help=cls.description,
            subcommand=True,
        )

        # Add the positional arg of service
        get_parser.add_argument(
            'service',
            choices=outputs,
            metavar='SERVICE',
            help=
            f"Service to pull configured outputs and their secrets, select from: {', '.join(outputs)}"
        )

        # Add the optional ability to pass multiple descriptors
        get_parser.add_argument(
            '--descriptors',
            '-d',
            nargs='+',
            default=False,
            help='Pass descriptor and service to pull back the relevant configuration')

        # Add the optional ability to pass service

    @classmethod
    def handler(cls, options, config):
        """Fetches the configuration for a service
        Args:
            options (argparse.Namespace): Basically a namedtuple with the service setting
            config (StreamAlert.config): The configuration of StreamAlert
        Returns:
            bool: False if errors occurred, True otherwise
        """
        service = options.service
        output = StreamAlertOutput.create_dispatcher(service, config)

        # Get the descriptors for the service. No need to check service
        # as this is handled by argparse choices
        configured_descriptors = [
            descriptor for descriptor in config["outputs"][service] if 'sample' not in descriptor
        ]

        # Set the descriptors to get the secrets for
        descriptors = options.descriptors or configured_descriptors

        LOGGER.debug('Getting secrets for service %s and descriptors %s', service, descriptors)

        credentials = []
        for descriptor in descriptors:
            if descriptor not in configured_descriptors:
                LOGGER.error('Invalid descriptor %s, it doesn\'t exist', descriptor)
                return False

            creds = output._load_creds(descriptor)  # pylint: disable=protected-access
            creds['descriptor'] = descriptor
            credentials.append(creds)

        print('\nService Name:', service)
        print(json.dumps(credentials, indent=2, sort_keys=True), '\n')


class OutputListSubCommand(CLICommand):
    description = 'List the currently configured outputs'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the output list subparser: manage.py output list [options]"""
        outputs = sorted(StreamAlertOutput.get_all_outputs().keys())

        list_parser = generate_subparser(
            subparser,
            'list',
            description=cls.description,
            help=cls.description,
            subcommand=True,
        )

        # Add the optional arg of service
        list_parser.add_argument(
            '--service',
            '-s',
            choices=outputs,
            default=outputs,
            nargs='*',
            metavar='SERVICE',
            help=
            f"Pass Services to list configured output descriptors, select from: {', '.join(outputs)}"
        )

    @classmethod
    def handler(cls, options, config):
        """List configured outputs
        Args:
            options (argparse.Namespace): Basically a namedtuple with the service setting
            config (StreamAlert.config): The configuration of StreamAlert
        Returns:
            bool: False if errors occurred, True otherwise
        """
        outputs = config["outputs"]

        print("\nConfigured outputs 'service:descriptor':")
        for output in options.service:
            if output not in outputs:
                continue
            for descriptor in outputs[output]:
                print(f"\t{output}:{descriptor}")
            print()  # ensure a newline between each service for easier reading

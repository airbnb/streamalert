import argparse
import os
import sys
import time

from streamalert.streamquery.command.processor import CommandProcessor
from streamalert.streamquery.config.services import configure_container
from streamalert.streamquery.container.container import ServiceContainer
from streamalert.streamquery.state.state_manager import FileWritingStateManager
from streamalert.streamquery.config.laptop_prod_conf import parameters as prod_parameters
from streamalert.streamquery.config.laptop_stage_conf import parameters as stage_parameters

_COMMAND_NAME = 'AthenaSchemaAnalyzer'


class StreamQueryCommand:
    def __init__(self):
        self._options = {}
        self._service_container = None
        self._state_manager = None
        self._logger = None

        self.initialize()

    @staticmethod
    def parse_options():
        """Parse arguments from command line"""
        parser_usage = '''
    $ python streamquery/run.py 


Description:

    Runs StreamQuery and all packs that are configured.

Sample Usage:

    $ python run.py

Options:

    None.

Flags:

    -v|--verbose        Increase log level to DEBUG, outputting more information.
    -p|--production     Sends data to production CSIRT, instead of stage

        '''
        command = argparse.ArgumentParser(usage=parser_usage,
                                          description=sys.modules[__name__].__doc__)

        command.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                             help='Increase log level to DEBUG')
        command.add_argument('-p', '--production', dest='production', action='store_true',
                             help='Send to production Kinesis')

        return command.parse_args()

    def initialize(self):
        self._options = self.parse_options()

        # Configure the container
        if self._options.production:
            parameters = prod_parameters
        else:
            parameters = stage_parameters

        parameters['log_level'] = 'DEBUG' if self._options.verbose else 'INFO'

        self._service_container = ServiceContainer(parameters)
        configure_container(self._service_container)

        # Notify the container is set up properly now
        self._logger = self._service_container.get('logger')
        self._logger.debug(
            'ServiceContainer parameters: %s', parameters
        )

        self._state_manager = FileWritingStateManager(
            self._service_container.get('state_manager'),
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                '../../cache/cache.json'
            ),
            self._logger
        )
        self._state_manager.load_from_file()

    def execute(self):
        """
        Do all the things!
        """

        try:
            processor = self._service_container.get('command_processor')  # type: CommandProcessor

            done = False
            while not done:
                done = processor.nonblocking_single_pass()

                if not done:
                    time.sleep(5)

        except RuntimeError as e:
            self._logger.error('- FATAL ERROR -')
            self._logger.error(e)
        finally:
            self._state_manager.write_to_file()
            self._logger.info('Script Completed')

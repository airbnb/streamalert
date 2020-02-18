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
from datetime import datetime

from streamalert.scheduled_queries.command.processor import CommandProcessor
from streamalert.scheduled_queries.config.services import configure_container
from streamalert.scheduled_queries.container.container import ServiceContainer
from streamalert.scheduled_queries.state.state_manager import StepFunctionStateManager, StateManager

from streamalert.scheduled_queries.config.lambda_conf import parameters


class ScheduledQueries:

    def __init__(self):
        # Boot the service container
        self._service_container = ServiceContainer(parameters)
        configure_container(self._service_container)

        self._logger = self._service_container.get('logger')

    def run(self, event):
        """Ensure the Lambda function's Handler is set to: 'lambda.handler' """

        # Start the function
        logger = self._logger
        logger.info('Running scheduled_queries lambda handler')
        logger.debug(
            'Invocation event: %s', event
        )
        logger.debug(
            'ServiceContainer parameters: %s', parameters
        )

        # Load up any prior state from the event passed in from the StepFunction
        state_manager_loader = StepFunctionStateManager(
            self._service_container.get('state_manager'),
            logger
        )
        state_manager_loader.load_from_step_function_event(event)

        # Wind the clock as part of the setup operation, if necessary
        state_manager = self._service_container.get('state_manager')  # type: StateManager
        clock = self._service_container.get('clock')
        isotime = state_manager.get('streamquery_configuration', {}).get('clock', False)
        if isotime:
            clock_datetime = datetime.strptime(isotime, "%Y-%m-%dT%H:%M:%SZ")
            clock.time_machine(clock_datetime)
            logger.info('Winding clock to %s...', clock.now)
        else:
            logger.warning('No clock configuration provided. Defaulting to %s', clock.now)

        # Execute a single pass of the StreamQuery runtime
        processor = self._service_container.get('command_processor')  # type: CommandProcessor
        done = processor.nonblocking_single_pass()

        # Set the updated state into the response
        #   The step function as-written currently looks specifically for $.done and
        #   $.continue and expects both of them to be present AND to be adopt exact
        #   numeric values
        response = {
            'done': 1 if done else 0,
            'continue': 1,
        }
        state_manager_loader.write_to_step_function_response(response)

        return response

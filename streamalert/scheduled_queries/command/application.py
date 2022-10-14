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
from streamalert.scheduled_queries.config.lambda_conf import \
    get_streamquery_env_vars
from streamalert.scheduled_queries.config.services import ApplicationServices


class ScheduledQueries:
    def __init__(self):
        # Ready all services
        self._services = ApplicationServices()

    def run(self, event):
        """The main application execution.

        StreamQuery executions are configured by two external sources. ENVIRONMENT variables and
        the input event. ENVIRONMENT variables help configure the application at deployment,
        whereas the input event tracks state within a single state machine.

        FIXME (Ryxias)
          We should re-evaluate which environment variables can be deployed via configuration files
          instead of being embedded into Terraform configurations.

        By design, StreamQuery's executions should be nonblocking. Waiting on Athena to complete
        many query executions is a waste of Lambda execution time, so StreamQuery is designed to
        fire-and-forget Athena queries. Upon first execution, query execution ids are saved into
        the state machine. Subsequent executions check the statuses of these queries, and dispatch
        the results of successful queries to StreamAlert. This process repeats until all scheduled
        queries are dispatched.

        Params:
            event (dict)
                The input event, which represents the state of the state machine.

                StreamQuery expects a very specific structure to the event. See StateManager or
                StepFunctionStateManager for more details.

        Returns:
            dict: The final state of the state machine.
        """

        # Start the function
        self._services.logger.info('Running scheduled_queries lambda handler')
        self._services.logger.debug('Invocation event: %s', event)
        self._services.logger.debug('ServiceContainer parameters: %s', get_streamquery_env_vars())

        # Load up any prior state from the event passed in from the StepFunction
        state_manager_loader = self._services.create_step_function_state_manager()
        state_manager_loader.load_from_step_function_event(event)

        # Execute a single pass of the StreamQuery runtime
        done = self._services.command_processor.nonblocking_single_pass()

        # Set the updated state into the response
        #   The step function as-written currently looks specifically for $.done and
        #   $.continue and expects both of them to be present AND to be adopt exact
        #   numeric values
        #
        #   When 'continue' is set to 1, the state machine will go into a waiting state, then
        #   re-execute this Lambda function again. When 'done' is set to 1, the state machine
        #   is considered complete and will not execute again. This should only happen if all
        #   scheduled queries have completed or failed.
        #
        # @see terraform/modules/tf_scheduled_queries/step_function.tf
        response = {
            'done': 1 if done else 0,
            'continue': 1,
        }
        state_manager_loader.write_to_step_function_response(response)

        return response

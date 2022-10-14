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


class StateManager:
    """Encapsulation of a caching system that is currently backed by the filesystem

    The "state" of a StreamQuery execution is encapsulated by
    """
    def __init__(self, logger=None):
        self._logger = logger

        self._data = {}

    def set(self, key, value):
        self._data[key] = value

    def has(self, key):
        return key in self._data

    def get(self, key, fallback=None):
        return self._data.get(key, fallback)

    def delete(self, key):
        del self._data[key]

    @property
    def keys(self):
        return list(self._data.keys())

    def _dangerously_set_all_data(self, data):
        """
        This method is NOT intended to be used by any classes outside of this module.
        """
        self._data = data

    def _dangerously_get_all_data(self):
        """
        This method is NOT intended to be used by any classes outside of this module.
        """
        return self._data


class StepFunctionStateManager:
    """State management when using AWS Step Functions

    The State of a step function is stored in a JSON blob that is passed from one State Machine
    state to the next. In states that execute Lambda functions, the state is passed in via the
    JSON event trigger.
    """
    def __init__(self, state_manager, logger, clock):
        self._state_manager = state_manager
        self._logger = logger
        self._clock = clock

    def load_from_step_function_event(self, event):
        """Given a lambda input event, loads the execution state of this StreamQuery iteration.

        When using Step Functions, lambda receives the state machine's state as the input event.

        ON FIRST execution, the expected event looks like this:

        {
          "name": "streamquery_cloudwatch_trigger",
          "event_id": "abcdabcd-1234-5678-1234-000001200000",
          "source_arn": "arn:aws:events:us-east-1:123456789012:rule/myprefix_schedule_thing",
          "streamquery_configuration": {
            "clock": "2020-02-18T23:55:16Z",
            "tags": [
              "hourly",
              "production"
            ]
          }
        }

        This represents the state of the Step Function state machine when it is first triggered
        by CloudWatch. In the above event, the event is generated via CloudWatch. The
        "streamquery_configuration" node is used to configure the lambda execution.

            @see terraform/modules/tf_scheduled_queries/cloudwatch_schedule.tf


        Henceforth, the "state" is always stored under a single key, "step_function_state".
        In these subsequent executions, the expected input event looks like this:

        {
          "done": 0,
          "continue": 1,
          "step_function_state": {
            "streamquery_configuration": {
              "clock": "2020-02-18T23:55:16Z",
              "tags": [
                "hourly",
                "production"
              ]
            },
            "my_query": {
              "query_execution_id": "70e509ed-c992-4096-8882-6bb070578347"
            },
            "my_other_query": {
              "query_execution_id": "b56cf6f3-d760-4abe-9345-fccd9cfa05e8"
            },
            "my_done_query": {
              "query_execution_id": "beeffc15-7608-48b4-89a4-a8e7ea81c5e6",
              "sent_to_streamalert": true
            }
            ...
          }
        }

        This "step_function_state" stores both the configuration (tags & clock), as well as the
        execution states of the scheduled queries.

        The "done" and "continue" flags at the stop of the event are
        """
        # pylint: disable=protected-access
        self._state_manager._dangerously_set_all_data(event.get('step_function_state', {}))
        self._logger.info('Successfully loaded from Step Function Event')

        # Special; The first time we execute the function, our "step_function_state" is empty, so
        # we will not have the streamquery_configuration set up. This code loads it from the
        # input event. Henceforth, this "streamquery_configuration" will be saved to and loaded
        # from "step_function_state".
        if 'streamquery_configuration' in event:
            # We expect 2 keys to exist, passed in from the CloudWatch rule input transformer:
            #   - clock: ISO timestamp in UTC
            #   - tags:  Array of strings
            self._logger.info('Loading configuration from first-run...')
            self._state_manager.set('streamquery_configuration', event['streamquery_configuration'])

        if isotime := self._state_manager.get('streamquery_configuration', {}).get('clock', False):
            clock_datetime = datetime.strptime(isotime, "%Y-%m-%dT%H:%M:%SZ")
            self._clock.time_machine(clock_datetime)
            self._logger.info('Winding clock to %s...', self._clock.now)
        else:
            self._logger.warning('No clock configuration provided. Defaulting to %s',
                                 self._clock.now)

    def write_to_step_function_response(self, response):
        response.update({
            # pylint: disable=protected-access
            'step_function_state': self._state_manager._dangerously_get_all_data(),
        })

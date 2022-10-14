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
from unittest.mock import MagicMock

from streamalert.scheduled_queries.state.state_manager import (
    StateManager, StepFunctionStateManager)


class TestStateManager:
    def __init__(self):
        self._state_manager = None
        self._logger = None

    def setup(self):
        self._logger = MagicMock(name='MockLogger')
        self._state_manager = StateManager(logger=self._logger)

    def test_has_set_get(self):
        """StreamQuery - StateManager - has, set, get"""
        key = 'aaa'
        assert not self._state_manager.has(key)

        self._state_manager.set(key, 'bbbbb')

        assert self._state_manager.has(key)
        assert self._state_manager.get(key) == 'bbbbb'

    def test_keys(self):
        """StreamQuery - StateManager - keys"""
        self._state_manager.set('aaa', 'bbbbb')
        self._state_manager.set('ccc', 'ddddd')

        assert self._state_manager.keys == ['aaa', 'ccc']

    # pylint: disable=protected-access
    def test_data(self):
        """StreamQuery - StateManager - data"""
        self._state_manager.set('aaa', 'bbbbb')
        self._state_manager.set('ccc', 'ddddd')

        assert (
            self._state_manager._dangerously_get_all_data() ==
            {'aaa': 'bbbbb', 'ccc': 'ddddd'})


class TestStepFunctionStateManager:
    def __init__(self):
        self._state_manager = None
        self._logger = None
        self._clock = None
        self._sfsm = None

    def setup(self):
        self._logger = MagicMock(name='MockLogger')
        self._clock = MagicMock(name='Clock')
        self._state_manager = StateManager(logger=self._logger)
        self._sfsm = StepFunctionStateManager(
            state_manager=self._state_manager,
            logger=self._logger,
            clock=self._clock
        )

    def test_has_load_write_empty(self):
        """StreamQuery - StepFunctionStateManager - load and write"""
        self._sfsm.load_from_step_function_event({})

        self._state_manager.set('asdf', 'qwerty')

        response = {
            'blah': '?'
        }
        self._sfsm.write_to_step_function_response(response)

        assert response == {
            'blah': '?',
            'step_function_state': {
                'asdf': 'qwerty'
            }
        }

    def test_first_load_will_properly_set_clock(self):
        """StreamQuery - StepFunctionStateManager - First load sets clock"""
        self._sfsm.load_from_step_function_event({
            "streamquery_configuration": {
                "clock": "2020-02-18T23:55:16Z",
                "tags": [
                    "hourly",
                    "production"
                ]
            }
        })

        self._clock.time_machine.assert_called_with(datetime(2020, 2, 18, 23, 55, 16))

    def test_subsequent_load_will_properly_set_clock(self):
        """StreamQuery - StepFunctionStateManager - Subsequent load sets clock"""
        self._sfsm.load_from_step_function_event({
            "step_function_state": {
                "streamquery_configuration": {
                    "clock": "2020-02-18T23:55:16Z",
                    "tags": [
                        "hourly",
                        "production"
                    ]
                }
            }
        })

        self._clock.time_machine.assert_called_with(datetime(2020, 2, 18, 23, 55, 16))

    def test_load_will_properly_set_tags(self):
        """StreamQuery - StepFunctionStateManager - Load will set tags"""
        self._sfsm.load_from_step_function_event({
            "step_function_state": {
                "streamquery_configuration": {
                    "clock": "2020-02-18T23:55:16Z",
                    "tags": [
                        "hourly",
                        "production"
                    ]
                }
            }
        })

        assert (
            self._state_manager.get('streamquery_configuration').get('tags') ==
            ['hourly', 'production'])

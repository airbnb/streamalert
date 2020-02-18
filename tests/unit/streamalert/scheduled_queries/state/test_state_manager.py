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
import os

from mock import MagicMock
from nose.tools import assert_equals, assert_true, assert_false

from streamalert.scheduled_queries.state.state_manager import (
    FileWritingStateManager,
    StateManager,
    StepFunctionStateManager,
)


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
        assert_false(self._state_manager.has(key))

        self._state_manager.set(key, 'bbbbb')

        assert_true(self._state_manager.has(key))
        assert_equals(self._state_manager.get(key), 'bbbbb')

    def test_keys(self):
        """StreamQuery - StateManager - keys"""
        self._state_manager.set('aaa', 'bbbbb')
        self._state_manager.set('ccc', 'ddddd')

        assert_equals(self._state_manager.keys, ['aaa', 'ccc'])

    # pylint: disable=protected-access
    def test_data(self):
        """StreamQuery - StateManager - data"""
        self._state_manager.set('aaa', 'bbbbb')
        self._state_manager.set('ccc', 'ddddd')

        assert_equals(
            self._state_manager._dangerously_get_all_data(),
            {'aaa': 'bbbbb', 'ccc': 'ddddd'}
        )


class TestStepFunctionStateManager:
    def __init__(self):
        self._state_manager = None
        self._logger = None
        self._sfsm = None

    def setup(self):
        self._logger = MagicMock(name='MockLogger')
        self._state_manager = StateManager(logger=self._logger)
        self._sfsm = StepFunctionStateManager(
            state_manager=self._state_manager,
            logger=self._logger
        )

    def test_has_load_write_empty(self):
        """StreamQuery - StepFunctionStateManager - load and write"""
        self._sfsm.load_from_step_function_event({})

        self._state_manager.set('asdf', 'qwerty')

        response = {
            'blah': '?'
        }
        self._sfsm.write_to_step_function_response(response)

        assert_equals(response, {
            'blah': '?',
            'step_function_state': {
                'asdf': 'qwerty'
            }
        })


class TestFileWritingStateManager:

    @staticmethod
    def test_write_then_load():
        """StreamQuery - FileWritingStateManager"""
        logger = MagicMock(name='MockLogger')
        sm1 = StateManager(logger=logger)
        file = os.path.dirname(os.path.realpath(__file__)) + '/testfile.json'

        sm1.set('key1', 'value1')
        sm1.set('key2', 'value2')

        fm1 = FileWritingStateManager(sm1, file, logger)
        fm1.write_to_file()

        # Now a new file should be created with the keys and values

        sm2 = StateManager(logger=logger)

        assert_false(sm2.has('key1'))

        fm2 = FileWritingStateManager(sm2, file, logger)
        fm2.load_from_file()

        assert_true(sm2.has('key1'))
        assert_equals(sm2.get('key1'), 'value1')

        os.remove(file)

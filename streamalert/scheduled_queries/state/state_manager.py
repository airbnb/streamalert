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
import json


class StateManager:
    """Encapsulation of a caching system that is currently backed by the filesystem"""

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


class FileWritingStateManager:
    def __init__(self, state_manager, cache_file, logger):
        self._state_manager = state_manager
        self._cache_file = cache_file
        self._logger = logger

    def write_to_file(self):
        with open(self._cache_file, 'w+') as output:
            # pylint: disable=protected-access
            data = self._state_manager._dangerously_get_all_data()
            schema_string = json.dumps(data, indent=2, separators=(',', ': '))
            output.write(schema_string + '\n')  # Ensure a newline at the EOF
            self._logger.info('Successfully wrote to target file: %s', self._cache_file)

    def load_from_file(self):
        try:
            with open(self._cache_file, 'r+') as file:
                # pylint: disable=protected-access
                self._state_manager._dangerously_set_all_data(json.load(file))
        except FileNotFoundError:
            # Assume this is benign and that we simply haven't created a cache file yet
            return
        except json.decoder.JSONDecodeError:
            # The cache is corrupted
            self._logger.error('Cache corrupted. Rebuilding cache...')


class StepFunctionStateManager:
    def __init__(self, state_manager, logger):
        self._state_manager = state_manager
        self._logger = logger

    def load_from_step_function_event(self, event):
        # pylint: disable=protected-access
        self._state_manager._dangerously_set_all_data(event.get('step_function_state', {}))
        self._logger.info('Successfully loaded from Step Function Event')

        # Special; if the event contains this key we load the configuration:
        if 'streamquery_configuration' in event:
            # We expect 2 keys to exist, passed in from the CloudWatch rule input transformer:
            #   - clock: ISO timestamp in UTC
            #   - tags:  Array of strings
            self._logger.info('Loading configuration from first-run...')
            self._state_manager.set('streamquery_configuration', event['streamquery_configuration'])

    def write_to_step_function_response(self, response):
        response.update({
            # pylint: disable=protected-access
            'step_function_state': self._state_manager._dangerously_get_all_data(),
        })

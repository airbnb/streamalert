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
from streamalert.shared.logger import get_logger
from streamalert.shared.lookup_tables.drivers import EphemeralDriver
from streamalert.shared.lookup_tables.table import LookupTable

LOGGER = get_logger(__name__)


class ThreatIntelMocks:
    """Simple class to encapsulate the mocked threat intel results"""

    _MOCKS = {}

    @classmethod
    def add_fixtures(cls, fixtures):
        """Add test fixtures for Threat Intel to use with rule testing

        Threat Intel fixture configs should be in the following JSON format:
            [
              {
                "ioc_value": "1.1.1.2",
                "ioc_type": "ip",
                "sub_type": "mal_ip"
              }
            ]
        """
        # Clear out any old fixtures
        cls._MOCKS.clear()

        LOGGER.debug('Setting up threat intel fixture: %s', fixtures)
        cls._MOCKS = {value['ioc_value']: value for value in fixtures}

    @classmethod
    def get_mock_values(cls, values):
        """Return the function to mock out ThreatIntel._query

        This simply returns values from the log that are in the mock_ioc_values
        based on fixtures that match the provided rule_path
        """
        # rewrite to use dict items
        return {value: cls._MOCKS[value] for value in values if value in cls._MOCKS}


class LookupTableMocks:
    """Simple class to encapsulate the mocked lookup table results"""

    _MOCKS = {}

    @classmethod
    def add_fixtures(cls, fixtures):
        """Add test fixtures for Lookup Tables to use with rule testing

        LookupTable fixture configs should be in the following JSON format:
            {
              "table-name": {
                "lookup-key": [
                  "value"
                ]
              }
            }
        """
        LOGGER.debug('Setting up lookup table fixtures')
        cls._MOCKS = fixtures

    @classmethod
    def get_mock_values(cls):
        for key, value in cls._MOCKS.items():
            driver = EphemeralDriver(None)
            driver._cache = value  # pylint: disable=protected-access
            yield LookupTable(key, driver, None)

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
import os

from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


def mock_lookup_table_results():
    """Load test fixtures for Lookup Tables to use with rule testing"""
    mock_lookup_tables = dict()
    for root, _, fixture_files in os.walk('tests/integration/fixtures/lookup_tables/'):
        for fixture_file in fixture_files:
            with open(os.path.join(root, fixture_file), 'r') as json_file:
                mock_lookup_tables[os.path.splitext(fixture_file)[0]] = json.load(json_file)
class ThreatIntelMocks:
    """Simple class to encapsulate the mocked threat intel results"""

    return mock_lookup_tables
    _MOCKS = dict()

    @classmethod
    def add_fixtures(cls, rule_dir):
        """Load test fixtures for Threat Intel to use with rule testing

        Fixture files should be in the following JSON format:
            [
              {
                "ioc_value": "1.1.1.2",
                "ioc_type": "ip",
                "sub_type": "mal_ip"
              }
            ]
        """
        fixtures_dir = os.path.join(rule_dir, 'test_fixtures', 'threat_intel')

        LOGGER.debug('Setting up threat intel fixture files: %s', fixtures_dir)
        for item in os.listdir(fixtures_dir):
            full_path = os.path.join(fixtures_dir, item)

            # The priority is used during data retrieval to allow for overriding
            # fixtures defined at various levels of the folder structure
            priority = len(rule_dir.split(os.path.sep))
            try:
                with open(full_path, 'r') as json_file:
                    # See if there are multiple files in the same directory and merge them
                    values = cls._MOCKS.get(rule_dir, {})
                    values.update({value['ioc_value']: value for value in json.load(json_file)})
                    cls._MOCKS[rule_dir] = {
                        'priority': priority,
                        'values': values
                    }
            except ValueError:
                LOGGER.error('Unsupported fixture file: %s', full_path)

    @classmethod
    def remove_fixtures(cls, rule_dir):
        LOGGER.debug('Tearing down threat intel fixture files: %s', rule_dir)
        del cls._MOCKS[rule_dir]

    @classmethod
    def get_mock_values(cls, rule_path):
        def threat_intel_mock_query(ti_values):
            """Return the function to mock out ThreatIntel._query

            This simply returns values from the log that are in the mock_ioc_values
            based on fixtures that match the provided rule_path
            """
            # Sort descending on the priority during retrieval to get the most relevant data
            data = sorted(cls._MOCKS.items(), key=lambda v: v[1]['priority'], reverse=True)
            for key, value in data:
                if not rule_path.startswith(key):
                    continue

                results = [
                    value['values'][item] for item in ti_values if item in value['values']
                ]
                if results:
                    return results

            return []

        return threat_intel_mock_query

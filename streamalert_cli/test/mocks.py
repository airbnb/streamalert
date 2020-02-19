"""
Copyright 2017-present, Airbnb, Inc.

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


def mock_threat_intel_query_results():
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
    mock_ioc_values = dict()
    for root, _, fixture_files in os.walk('tests/integration/fixtures/threat_intel/'):
        for fixture_file in fixture_files:
            with open(os.path.join(root, fixture_file), 'r') as json_file:
                mock_ioc_values.update(
                    {value['ioc_value']: value for value in json.load(json_file)}
                )

    # Return the function to mock out ThreatIntel._query
    # This simply returns values from the log that are in the mock_ioc_values
    def _query(values):
        return [
            mock_ioc_values[value] for value in values if value in mock_ioc_values
        ]

    return _query


def mock_lookup_table_results():
    """Load test fixtures for Lookup Tables to use with rule testing"""
    mock_lookup_tables = dict()
    for root, _, fixture_files in os.walk('tests/integration/fixtures/lookup_tables/'):
        for fixture_file in fixture_files:
            with open(os.path.join(root, fixture_file), 'r') as json_file:
                mock_lookup_tables[os.path.splitext(fixture_file)[0]] = json.load(json_file)

    return mock_lookup_tables

"""
Copyright 2017-present Airbnb, Inc.

Licensed under the Apache License, Version 2.0 (the 'License');
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an 'AS IS' BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import json

import pytest


@pytest.mark.usefixtures('patcher')
def basic_test_file_json(**kwargs):
    return json.dumps([basic_test_event_data(**kwargs)])


@pytest.mark.usefixtures('patcher')
def basic_test_event_data(
        log='misc_log_type',
        service='unit-test-service',
        source='unit-test-source',
        override_data=None):
    result = {
        'data': {
            'key': 'value'
        },
        'description': 'Integration test event for unit testing',
        'log': log,
        'service': service,
        'source': source,
        'trigger_rules': [
            'misc_rule'
        ]
    }

    if override_data:
        del result['data']
        result['override_record'] = override_data
        result['log'] = 'override_log_type'

    return result

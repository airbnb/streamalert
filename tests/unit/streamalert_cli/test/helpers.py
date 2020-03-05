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

from nose.tools import nottest


@nottest
def basic_test_file_json():
    return json.dumps(basic_test_file_data())


@nottest
def basic_test_file_data():
    return [
        {
            'data': {
                'key': 'value'
            },
            'description': 'Integration test event for unit testing',
            'log': 'misc_log_type',
            'service': 'unit-test-service',
            'source': 'unit-test-source',
            'trigger_rules': [
                'misc_rule'
            ]
        }
    ]

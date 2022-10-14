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

from streamalert_cli import helpers


def test_record_to_schema_no_recurse():
    """CLI - Helpers - Record to Schema, Non-recursive"""

    record = {
        'dict': {
            'boolean': False,
            'integer': 123
        },
        'list': [],
        'string': 'this is a string',
        'float': 1234.56,
        'integer': 1234,
        'boolean': True
    }

    expected_result = {
        'dict': {},
        'list': [],
        'string': 'string',
        'float': 'float',
        'integer': 'integer',
        'boolean': 'boolean'
    }

    result = helpers.record_to_schema(record, recursive=False)

    assert result == expected_result


def test_record_to_schema_recurse():
    """CLI - Helpers - Record to Schema, Recursive"""

    record = {
        'dict': {
            'boolean': False,
            'integer': 123
        },
        'list': [],
        'string': 'this is a string',
        'float': 1234.56,
        'integer': 1234,
        'boolean': True
    }

    expected_result = {
        'dict': {
            'boolean': 'boolean',
            'integer': 'integer'
        },
        'list': [],
        'string': 'string',
        'float': 'float',
        'integer': 'integer',
        'boolean': 'boolean'
    }

    result = helpers.record_to_schema(record, recursive=True)

    assert result == expected_result

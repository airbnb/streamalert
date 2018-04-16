"""
Copyright 2017-present, Airbnb Inc.

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

from mock import mock_open, patch
from nose.tools import assert_equal, assert_false, assert_is_none, assert_items_equal

from stream_alert_cli import helpers


def test_load_test_file_list():
    """CLI - Helpers - Load Rule Test File - Good File (list)"""
    test_data = [{'data': {'field': 'value'}}]
    mock = mock_open(read_data=json.dumps(test_data))
    with patch('__builtin__.open', mock):
        event, error = helpers.load_test_file('no/path')

    assert_equal(event, test_data)
    assert_is_none(error)


def test_load_test_file_map():
    """CLI - Helpers - Load Rule Test File - Good File (map)"""
    test_data = {'records': [{'field': 'value'}]}
    mock = mock_open(read_data=json.dumps(test_data))
    with patch('__builtin__.open', mock):
        event, error = helpers.load_test_file('no/path')

    assert_equal(event, test_data['records'])
    assert_is_none(error)


def test_load_test_file_bad_value():
    """CLI - Helpers - Load Rule Test File - Bad Value"""
    mock = mock_open(read_data='bad json string')
    with patch('__builtin__.open', mock):
        event, error = helpers.load_test_file('no/path')

    assert_equal(event, [])
    assert_equal(error, 'Improperly formatted file (no/path): No JSON object could be decoded')


def test_load_test_file_bad_format():
    """CLI - Helpers - Load Rule Test File - Bad Format"""
    test_data = {'records': {'field': 'value'}}
    mock = mock_open(read_data=json.dumps(test_data))
    with patch('__builtin__.open', mock):
        event, error = helpers.load_test_file('no/path')

    assert_false(event)
    assert_equal(
        error,
        'Improperly formatted file (no/path): Test file must contain either '
        'a list of maps, or a list of '
        'maps preceeded with a `records` key')


def test_get_rule_test_files():
    """CLI - Helpers - Get Rule Test Files - Load Files"""
    with patch('os.walk') as mock_walk:
        mock_walk.return_value = [
            ('/root_dir', (), ('file.json', 'file2.json',)),
            ('/root_dir/sub_dir', (), ('subfile.json', 'subfile2.json')),
        ]

        file_info = helpers.get_rule_test_files('no/path')

        assert_items_equal(file_info.keys(), {'file', 'file2', 'subfile', 'subfile2'})


def test_get_rules_from_test_events():
    """CLI - Helpers - Get Rules From Test Events"""
    with patch('os.walk') as mock_walk:
        mock_walk.return_value = [('/root_dir', (), ('file.json',))]

        rules = ['rule_01', 'rule_02']
        test_data = {'records': [{'trigger_rules': rules}]}

        mock = mock_open(read_data=json.dumps(test_data))
        with patch('__builtin__.open', mock):

            returned_rules = helpers.get_rules_from_test_events('fake/path')

        assert_items_equal(rules, returned_rules)


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

    assert_equal(result, expected_result)


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

    assert_equal(result, expected_result)

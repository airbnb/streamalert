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

from stream_alert_cli import helpers

from mock import mock_open, patch
from nose.tools import assert_equal, assert_false, assert_is_none, assert_items_equal


def test_load_test_file():
    """Load Rule Test File - Good File"""
    test_data = {'records': []}
    mock = mock_open(read_data=json.dumps(test_data))
    with patch('__builtin__.open', mock):
        event, error = helpers.load_test_file('no/path')

    assert_equal(event, test_data)
    assert_is_none(error)


def test_load_test_file_bad_value():
    """Load Rule Test File - Bad Value"""
    mock = mock_open(read_data='bad json string')
    with patch('__builtin__.open', mock):
        event, error = helpers.load_test_file('no/path')

    assert_false(event)
    assert_equal(error, 'Improperly formatted file (no/path): No JSON object could be decoded')


def test_load_test_file_bad_format():
    """Load Rule Test File - Bad Format"""
    mock = mock_open(read_data=json.dumps({'record': []}))
    with patch('__builtin__.open', mock):
        event, error = helpers.load_test_file('no/path')

    assert_false(event)
    assert_equal(error, 'Improperly formatted file (no/path): File must be a dict (JSON '
                        'object) with top level key \'records\'')


def test_get_rule_test_files():
    """Get Rule Test Files - Load Files"""
    with patch('os.walk') as mock_walk:
        mock_walk.return_value = [
            ('/root_dir', (), ('file.json', 'file2.json',)),
            ('/root_dir/sub_dir', (), ('subfile.json', 'subfile2.json')),
        ]

        file_info = helpers.get_rule_test_files('no/path')

        assert_items_equal(file_info.keys(), {'file', 'file2', 'subfile', 'subfile2'})


def test_get_rules_from_test_events():
    """Get Rules From Test Events"""
    with patch('os.walk') as mock_walk:
        mock_walk.return_value = [('/root_dir', (), ('file.json',))]

        rules = ['rule_01', 'rule_02']
        test_data = {'records': [{'trigger_rules': rules}]}

        mock = mock_open(read_data=json.dumps(test_data))
        with patch('__builtin__.open', mock):

            returned_rules = helpers.get_rules_from_test_events('fake/path')

        assert_items_equal(rules, returned_rules)

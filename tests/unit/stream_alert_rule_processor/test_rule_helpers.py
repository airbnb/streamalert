# -*- coding: utf-8 -*-
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
import time

from nose.tools import assert_equal, assert_false, assert_true

from helpers import base


def test_starts_with_any():
    """Helpers - Starts With Any"""
    prefixes = {'a', 'hello'}
    assert_false(base.starts_with_any(None, prefixes))
    assert_false(base.starts_with_any('false', prefixes))
    assert_true(base.starts_with_any('alpha', prefixes))
    assert_true(base.starts_with_any('hello_world', prefixes))


def test_ends_with_any():
    """Helpers - Starts With Any"""
    suffixes = {'z', 'world'}
    assert_false(base.ends_with_any(None, suffixes))
    assert_false(base.ends_with_any('false', suffixes))
    assert_true(base.ends_with_any('oz', suffixes))
    assert_true(base.ends_with_any('hello_world', suffixes))


def test_contains_any():
    """Helpers - Contains Any"""
    substrings = {'stream', 'alert'}
    assert_false(base.contains_any(None, substrings))
    assert_false(base.contains_any('StreamAlert', substrings))  # case-sensitive
    assert_true(base.contains_any('streamalert', substrings))
    assert_true(base.contains_any('binaryalert', substrings))


def test_matches_any():
    """Helpers - Matches Any"""
    patterns = {'/root/*/file.txt', '*a*b*c*'}
    assert_false(base.matches_any(None, patterns))
    assert_false(base.matches_any('streamalert', patterns))
    assert_true(base.matches_any('/root/some/long/path/file.txt', patterns))
    assert_true(base.matches_any('abc', patterns))


def test_last_hour():
    """Helpers - Last Hour"""
    time_now = int(time.time())

    thirty_minutes_ago = time_now - 1800
    assert_equal(base.last_hour(thirty_minutes_ago), True)

    one_hour_ago = time_now - 3600
    assert_equal(base.last_hour(one_hour_ago), True)

    two_hours_ago = time_now - 7200
    assert_equal(base.last_hour(two_hours_ago), False)


def test_fetch_values_by_datatype():
    """Helpers - Fetch values from a record by normalized type"""
    rec = {
        'account': 12345,
        'region': '123456123456',
        'detail': {
            'eventVersion': '...',
            'eventID': '...',
            'eventTime': '...',
            'additionalEventData': {
                'MFAUsed': 'Yes',
                'LoginTo': '...',
                'MobileVersion': 'No'
            },
            'requestParameters': None,
            'eventType': 'AwsConsoleSignIn',
            'responseElements': {
                'ConsoleLogin': '...'
            },
            'awsRegion': '...',
            'eventName': 'ConsoleLogin',
            'userIdentity': {
                'userName': 'alice',
                'type': 'Root',
                'principalId': '12345',
                'arn': 'arn:aws:iam::12345:root',
                'accountId': '12345'
            },
            'eventSource': '...',
            'userAgent': '...',
            'sourceIPAddress': '1.1.1.2',
            'recipientAccountId': '12345'
        },
        'detail-type': '...',
        'source': '1.1.1.2',
        'version': '1.05',
        'streamalert:normalization': {
            'ipv4': [['detail', 'sourceIPAddress'], ['source']],
            'username': [['detail', 'userIdentity', 'userName']]
        },
        'time': '...',
        'id': '12345',
        'resources': {
            'test': '...'
        }
    }
    assert_equal(len(base.fetch_values_by_datatype(rec, 'ipv4')), 2)
    assert_equal(len(base.fetch_values_by_datatype(rec, 'cmd')), 0)
    assert_equal(base.fetch_values_by_datatype(rec, 'username'), ['alice'])


def test_safe_json_loads_valid():
    """Helpers - Loading valid JSON"""
    json_str = '{"test": 0, "values": [1, 2, 3]}'
    loaded_json = base.safe_json_loads(json_str)

    assert_equal(type(loaded_json), dict)
    assert_true(loaded_json)
    assert_equal(loaded_json, {'test': 0, 'values': [1, 2, 3]})


def test_safe_json_loads_invalid():
    """Helpers - Loading invalid JSON"""
    json_str = 'invalid json string!!!!'
    loaded_json = base.safe_json_loads(json_str)

    assert_equal(type(loaded_json), dict)
    assert_false(loaded_json)
    assert_equal(loaded_json, {})

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

from nose.tools import assert_equal

from helpers import base


def test_in_set():
    """Helpers - In Set"""
    # basic example
    test_list = ['this', 'is', 'a9', 'test']
    data = 'test'
    result = base.in_set(data, test_list)
    assert_equal(result, True)

    # with globbing
    host_patterns = {'myhost*', 'yourhost*', 'ahost*'}
    myhost = 'myhost1232312321'
    yourhost = 'yourhost134931'
    ahost = 'ahost12321-test'

    result = all(base.in_set(host, host_patterns) for host in (myhost, yourhost, ahost))
    assert_equal(result, True)


def test_last_hour():
    """Helpers - Last Hour"""
    time_now = int(time.time())

    thirty_minutes_ago = time_now - 1800
    assert_equal(base.last_hour(thirty_minutes_ago), True)

    one_hour_ago = time_now - 3600
    assert_equal(base.last_hour(one_hour_ago), True)

    two_hours_ago = time_now - 7200
    assert_equal(base.last_hour(two_hours_ago), False)


def test_valid_ip():
    """Helpers - Valid IP"""
    test_ip_valid = '127.0.0.1'
    assert_equal(base.valid_ip(test_ip_valid), True)

    test_ip_invalid = 'test [1234]'
    assert_equal(base.valid_ip(test_ip_invalid), False)


def test_in_network():
    """Helpers - In Network"""
    cidrs = {
        '10.0.16.0/24',
        '10.0.17.0/24'
    }

    ip_in_cidr = '10.0.16.24'
    assert_equal(base.in_network(ip_in_cidr, cidrs), True)

    ip_not_in_cidr = '10.0.15.24'
    assert_equal(base.in_network(ip_not_in_cidr, cidrs), False)

def test_fetch_values_by_datatype():
    """Helpers - Fetch values from a record by normalized type"""
    rec = {
        u'account': 12345,
        u'region': '123456123456',
        u'detail': {
            u'eventVersion': u'...',
            u'eventID': u'...',
            u'eventTime': u'...',
            u'additionalEventData': {
                u'MFAUsed': u'Yes',
                u'LoginTo': u'...',
                u'MobileVersion': u'No'
            },
            u'requestParameters': None,
            u'eventType': u'AwsConsoleSignIn',
            u'responseElements': {
                u'ConsoleLogin': u'...'
            },
            u'awsRegion': u'...',
            u'eventName': u'ConsoleLogin',
            u'userIdentity': {
                u'type': u'Root',
                u'principalId': u'12345',
                u'arn': u'arn:aws:iam::12345:root',
                u'accountId': u'12345'
            },
            u'eventSource': u'...',
            u'userAgent': u'...',
            u'sourceIPAddress': u'1.1.1.2',
            u'recipientAccountId': u'12345'
        },
        u'detail-type': '...',
        u'source': '1.1.1.2',
        u'version': '1.05',
        'normalized_types': {
            'ipv4': [[u'detail', u'sourceIPAddress'], u'source']
        },
        u'time': '...',
        u'id': '12345',
        u'resources': {
            u'test': u'...'
        }
    }
    assert_equal(len(base.fetch_values_by_datatype(rec, 'ipv4')), 2)
    assert_equal(len(base.fetch_values_by_datatype(rec, 'cmd')), 0)

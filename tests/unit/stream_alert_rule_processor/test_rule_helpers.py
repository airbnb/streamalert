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

from nose.tools import assert_equal, with_setup

from helpers import base
from stream_alert.rule_processor.threat_intel import StreamThreatIntel


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
        'normalized_types': {
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

def setup():
    """Setup before each method"""
    test_config = {
        'threat_intel': {
            'enabled': True,
            'mapping': {
                'sourceAddress': 'ip',
                'destinationDomain': 'domain',
                'fileHash': 'md5'
            }
        }
    }
    StreamThreatIntel.load_intelligence(test_config, 'tests/unit/fixtures')

def teardown():
    """Clear class variable after each method"""
    StreamThreatIntel.get_intelligence().clear()

@with_setup(setup=setup, teardown=teardown)
def test_detect_ioc_rule():
    """Helpers - There is IOC detected in a record"""
    rec = {
        'account': 12345,
        'region': '123456123456',
        'detail': {
            'eventSource': '...',
            'userAgent': '...',
            'sourceIPAddress': '90.163.54.11',
            'recipientAccountId': '12345'
        },
        'detail-type': '...',
        'source': '1.1.1.2',
        'version': '1.05',
        'normalized_types': {
            'sourceAddress': [['detail', 'sourceIPAddress'], ['source']],
            'username': [['detail', 'userIdentity', 'userName']]
        },
        'time': '...',
        'id': '12345',
        'resources': {
            'test': '...'
        }
    }

    ioc_result = base.is_ioc(rec)
    assert_equal(ioc_result, True)
    expected_ioc_info = {
        'type': 'ip',
        'value': '90.163.54.11'
    }
    assert_equal(rec['streamalert:ioc'], expected_ioc_info)

@with_setup(setup=setup, teardown=teardown)
def test_is_ioc_with_no_matching():
    """Helpers - No known IOC detected in a record"""
    rec = {
        'account': 12345,
        'region': '123456123456',
        'detail': {
            'eventSource': '...',
            'userAgent': '...',
            'sourceIPAddress': '1.1.1.2',
            'recipientAccountId': '12345'
        },
        'detail-type': '...',
        'source': '1.1.1.2',
        'version': '1.05',
        'normalized_types': {
            'sourceAddress': [['detail', 'sourceIPAddress'], ['source']],
            'username': [['detail', 'userIdentity', 'userName']]
        },
        'time': '...',
        'id': '12345',
        'resources': {
            'test': '...'
        }
    }

    ioc_result = base.is_ioc(rec)
    assert_equal(ioc_result, False)

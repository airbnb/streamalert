"""Tests for stream_alert/shared/utils.py"""
from nose.tools import assert_equal, assert_false

from stream_alert.shared import utils


def test_valid_ip():
    """Utils - Valid IP"""
    test_ip_valid = '127.0.0.1'
    assert_equal(utils.valid_ip(test_ip_valid), True)

    test_ip_invalid = 'test [1234]'
    assert_equal(utils.valid_ip(test_ip_invalid), False)


def test_in_network_invalid_ip():
    """Utils - In Network - Invalid IP"""
    assert_false(utils.in_network('a string that is not an ip', {'10.0.100.0/24'}))


def test_in_network_invalid_cidr():
    """Utils - In Network - Invalid CIDR"""
    assert_false(utils.in_network('127.0.0.1', {'not a cidr'}))


def test_in_network():
    """Utils - In Network"""
    cidrs = {
        '10.0.16.0/24',
        '10.0.17.0/24'
    }

    ip_in_cidr = '10.0.16.24'
    assert_equal(utils.in_network(ip_in_cidr, cidrs), True)

    ip_not_in_cidr = '10.0.15.24'
    assert_equal(utils.in_network(ip_not_in_cidr, cidrs), False)


def test_get_first_key():
    """Utils - Get First Key"""
    data = {
        'path': 'ABC',
        'details': {
            'parent': {
                'path': 'DEF',
            }
        },
        'empty_dict': {},
        'empty_list': [],
        'events': [
            {
                'path': 'GHI'
            }
        ]
    }
    # 'path' is a top-level key and so should always be returned first
    assert_equal('ABC', utils.get_first_key(data, 'path'))

    # dicts and lists can be returned as well
    assert_equal(data['details'], utils.get_first_key(data, 'details'))

    # None is returned by default if no value is found
    assert_equal(None, utils.get_first_key(data, 'no-key-found'))

    # Custom default value is returned if specified
    assert_equal({}, utils.get_first_key(data, 'no-key-found', {}))


def test_get_keys():
    """Utils - Get Keys"""
    data = {
        'path': 'ABC',
        'details': {
            'parent': {
                'path': 'DEF'
            }
        },
        'empty_dict': {},
        'empty_list': [],
        'events': [
            {
                'path': 'GHI'
            }
        ]
    }
    assert_equal({'ABC', 'DEF', 'GHI'}, set(utils.get_keys(data, 'path')))
    assert_equal(2, len(utils.get_keys(data, 'path', max_matches=2)))
    assert_equal([], utils.get_keys({}, 'path'))

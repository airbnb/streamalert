"""Tests for streamalert/shared/utils.py"""
import json

from streamalert.shared import utils
from streamalert.shared.normalize import Normalizer

MOCK_RECORD_ID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'


def test_valid_ip():
    """Utils - Valid IP"""
    test_ip_valid = '127.0.0.1'
    assert utils.valid_ip(test_ip_valid)

    test_ip_invalid = 'test [1234]'
    assert utils.valid_ip(test_ip_invalid) == False


def test_in_network_invalid_ip():
    """Utils - In Network - Invalid IP"""
    assert not utils.in_network('a string that is not an ip', {'10.0.100.0/24'})


def test_in_network_invalid_cidr():
    """Utils - In Network - Invalid CIDR"""
    assert not utils.in_network('127.0.0.1', {'not a cidr'})


def test_in_network():
    """Utils - In Network"""
    cidrs = {
        '10.0.16.0/24',
        '10.0.17.0/24'
    }

    ip_in_cidr = '10.0.16.24'
    assert utils.in_network(ip_in_cidr, cidrs)

    ip_not_in_cidr = '10.0.15.24'
    assert utils.in_network(ip_not_in_cidr, cidrs) == False


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
    assert 'ABC' == utils.get_first_key(data, 'path')

    # dicts and lists can be returned as well
    assert data['details'] == utils.get_first_key(data, 'details')

    # None is returned by default if no value is found
    assert None is utils.get_first_key(data, 'no-key-found')

    # Custom default value is returned if specified
    assert {} == utils.get_first_key(data, 'no-key-found', {})


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
    assert {'ABC', 'DEF', 'GHI'} == set(utils.get_keys(data, 'path'))
    assert 2 == len(utils.get_keys(data, 'path', max_matches=2))
    assert [] == utils.get_keys({}, 'path')


def generate_categorized_records(normalized=False, count=2):
    """Generate categorized records by source types"""
    json_data = [{f'key_{cnt}': f'value_{cnt}'} for cnt in range(count)]

    if normalized:
        for data in json_data:
            data[Normalizer.NORMALIZATION_KEY] = {
                'normalized_type1': [
                    {
                        'values': ['value1'],
                        'function': None
                    }
                ],
                'normalized_type2': [
                    {
                        'values': ['value2', 'value3'],
                        'function': None,
                        'send_to_artifacts': True
                    }
                ],
                'normalized_type3': [
                    {
                        'values': ['value2', 'value3'],
                        'function': None,
                        'send_to_artifacts': False
                    }
                ]
            }

    return {
        'log_type_01_sub_type_01': json_data
    }


def generate_artifacts(firehose_records=False):
    """Generate sample artifacts for unit tests"""

    normalized_values = [
        ('normalized_type1', 'value1'),
        ('normalized_type2', 'value2'),
        ('normalized_type2', 'value3'),
        ('normalized_type1', 'value1'),
        ('normalized_type2', 'value2'),
        ('normalized_type2', 'value3')
    ]
    artifacts = [
        {
            'function': 'None',
            'streamalert_record_id': MOCK_RECORD_ID,
            'source_type': 'log_type_01_sub_type_01',
            'type': type,
            'value': value
        } for type, value in normalized_values
    ]

    if firehose_records:
        return [
            json.dumps(artifact, separators=(',', ':')) + '\n' for artifact in artifacts
        ]

    return artifacts

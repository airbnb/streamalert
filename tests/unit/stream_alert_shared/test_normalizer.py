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
from mock import patch
from nose.tools import assert_equal

from stream_alert.shared.normalize import Normalizer


class TestNormalizer(object):
    """Normalizer tests"""
    # pylint: disable=protected-access,no-self-use,attribute-defined-outside-init

    def teardown(self):
        Normalizer._types_config = None

    @classmethod
    def _test_record(cls):
        return {
            'account': 123456,
            'region': 'region_name',
            'detail': {
                'awsRegion': 'region_name',
                'source': '1.1.1.2',
                'userIdentity': {
                    'userName': 'Alice',
                    'invokedBy': 'signin.amazonaws.com'
                }
            },
            'sourceIPAddress': '1.1.1.3'
        }

    def test_match_types(self):
        """Normalizer - Match Types"""
        normalized_types = {
            'region': ['region', 'awsRegion'],
            'sourceAccount': ['account', 'accountId'],
            'ipv4': ['destination', 'source', 'sourceIPAddress']
        }
        expected_results = {
            'sourceAccount': [123456],
            'ipv4': ['1.1.1.2', '1.1.1.3'],
            'region': ['region_name']
        }

        results = Normalizer.match_types(self._test_record(), normalized_types)
        assert_equal(results, expected_results)

    def test_match_types_multiple(self):
        """Normalizer - Match Types, Mutiple Sub-keys"""
        normalized_types = {
            'account': ['account'],
            'region': ['region', 'awsRegion'],
            'ipv4': ['destination', 'source', 'sourceIPAddress'],
            'userName': ['userName', 'owner', 'invokedBy']
        }
        expected_results = {
            'account': [123456],
            'ipv4': ['1.1.1.2', '1.1.1.3'],
            'region': ['region_name'],
            'userName': ['Alice', 'signin.amazonaws.com']
        }

        results = Normalizer.match_types(self._test_record(), normalized_types)
        assert_equal(results, expected_results)

    def test_match_types_list(self):
        """Normalizer - Match Types, List of Values"""
        normalized_types = {
            'ipv4': ['sourceIPAddress'],
        }
        expected_results = {
            'ipv4': ['1.1.1.2', '1.1.1.3']
        }

        test_record = {
            'account': 123456,
            'sourceIPAddress': ['1.1.1.2', '1.1.1.3']
        }

        results = Normalizer.match_types(test_record, normalized_types)
        assert_equal(results, expected_results)

    def test_normalize(self):
        """Normalizer - Normalize"""
        log_type = 'cloudtrail'
        Normalizer._types_config = {
            log_type: {
                'region': {
                    'region',
                    'awsRegion'
                },
                'sourceAccount': {
                    'account',
                    'accountId'
                }
            }
        }
        record = self._test_record()
        Normalizer.normalize(record, log_type)

        expected_record = {
            'account': 123456,
            'region': 'region_name',
            'detail': {
                'awsRegion': 'region_name',
                'source': '1.1.1.2',
                'userIdentity': {
                    "userName": "Alice",
                    "invokedBy": "signin.amazonaws.com"
                }
            },
            'sourceIPAddress': '1.1.1.3',
            'streamalert:normalization': {
                'region': ['region_name'],
                'sourceAccount': [123456]
            }
        }

        assert_equal(record, expected_record)

    @patch('logging.Logger.debug')
    def test_normalize_none_defined(self, log_mock):
        """Normalizer - Normalize, No Types Defined"""
        log_type = 'cloudtrail'
        Normalizer._types_config = {}
        Normalizer.normalize(self._test_record(), log_type)
        log_mock.assert_called_with('No normalized types defined for log type: %s', log_type)

    def test_key_does_not_exist(self):
        """Normalizer - Normalize, Key Does Not Exist"""
        test_record = {
            'accountId': 123456,
            'region': 'region_name'
        }

        normalized_types = {
            'region': ['region', 'awsRegion'],
            'sourceAccount': ['account', 'accountId'],
            # There is no IP value in record, so normalization should not include this
            'ipv4': ['sourceIPAddress']
        }
        expected_results = {
            'sourceAccount': [123456],
            'region': ['region_name']
        }

        results = Normalizer.match_types(test_record, normalized_types)
        assert_equal(results, expected_results)

    def test_empty_value(self):
        """Normalizer - Normalize, Empty Value"""
        test_record = {
            'account': 123456,
            'region': ''  # This value is empty so should not be stored
        }

        normalized_types = {
            'region': ['region', 'awsRegion'],
            'sourceAccount': ['account', 'accountId'],
            'ipv4': ['sourceIPAddress']
        }
        expected_results = {
            'sourceAccount': [123456]
        }

        results = Normalizer.match_types(test_record, normalized_types)
        assert_equal(results, expected_results)

    def test_get_values_for_normalized_type(self):
        """Normalizer - Get Values for Normalized Type"""
        expected_result = {'1.1.1.3'}
        record = {
            'sourceIPAddress': '1.1.1.3',
            'streamalert:normalization': {
                'ip_v4': expected_result,
            }
        }

        assert_equal(Normalizer.get_values_for_normalized_type(record, 'ip_v4'), expected_result)

    def test_get_values_for_normalized_type_none(self):
        """Normalizer - Get Values for Normalized Type, None"""
        record = {
            'sourceIPAddress': '1.1.1.3',
            'streamalert:normalization': {}
        }

        assert_equal(Normalizer.get_values_for_normalized_type(record, 'ip_v4'), set())

    def test_load_from_config(self):
        """Normalizer - Load From Config"""
        config = {
            'normalized_types': {
                'cloudtrail': {
                    'region': [
                        'region',
                        'awsRegion'
                    ],
                    'sourceAccount': [
                        'account',
                        'accountId'
                    ]
                }
            }
        }
        normalizer = Normalizer.load_from_config(config)
        expected_config = {
            'cloudtrail': {
                'region': [
                    'region',
                    'awsRegion'
                ],
                'sourceAccount': [
                    'account',
                    'accountId'
                ]
            }
        }
        assert_equal(normalizer, Normalizer)
        assert_equal(normalizer._types_config, expected_config)

    def test_load_from_config_empty(self):
        """Normalizer - Load From Config, Empty"""
        normalizer = Normalizer.load_from_config({})
        assert_equal(normalizer, Normalizer)
        assert_equal(normalizer._types_config, None)

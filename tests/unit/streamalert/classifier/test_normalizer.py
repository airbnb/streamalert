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

from stream_alert.classifier.normalize import Normalizer


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
                    "userName": "Alice",
                    "invokedBy": "signin.amazonaws.com"
                }
            },
            'sourceIPAddress': '1.1.1.2'
        }

    def test_match_types(self):
        """Normalizer - Match Types"""
        normalized_types = {
            'region': ['region', 'awsRegion'],
            'sourceAccount': ['account', 'accountId'],
            'ipv4': ['destination', 'source', 'sourceIPAddress']
        }
        expected_results = {
            'sourceAccount': [['account']],
            'ipv4': [['sourceIPAddress'], ['detail', 'source']],
            'region': [['region'], ['detail', 'awsRegion']]
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
            'account': [['account']],
            'ipv4': [['sourceIPAddress'], ['detail', 'source']],
            'region': [['region'], ['detail', 'awsRegion']],
            'userName': [
                ['detail', 'userIdentity', 'userName'],
                ['detail', 'userIdentity', 'invokedBy']
            ]
        }

        results = Normalizer.match_types(self._test_record(), normalized_types)
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
            'sourceIPAddress': '1.1.1.2',
            'streamalert:normalization': {
                'region': [['region'], ['detail', 'awsRegion']],
                'sourceAccount': [['account']]
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

    def test_normalize_bad_normalized_key(self):
        """Normalizer - Normalize, Bad Key(s)"""
        log_type = 'cloudtrail'
        bad_types = {
            'bad_key_01',
            'bad_key_02'
        }
        Normalizer._types_config = {
            log_type: {
                'bad_type': bad_types
            }
        }
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
            'sourceIPAddress': '1.1.1.2',
            'streamalert:normalization': {
                'bad_type': [],
            }
        }

        record = self._test_record()
        Normalizer.normalize(record, log_type)
        assert_equal(record, expected_record)

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

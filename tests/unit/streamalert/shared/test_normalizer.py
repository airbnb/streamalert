"""
Copyright 2017-present Airbnb, Inc.

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
from unittest.mock import Mock, patch

import pytest

from streamalert.shared.exceptions import ConfigError
from streamalert.shared.normalize import NormalizedType, Normalizer
from tests.unit.streamalert.shared.test_utils import MOCK_RECORD_ID


class TestNormalizer:
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

    @classmethod
    def _normalized_type_ip(cls):
        return NormalizedType(
            'test_log_type',
            'ip_address',
            [
                {
                    'path': ['sourceIPAddress'],
                    'function': 'source ip address'
                },
                {
                    'path': ['detail', 'source'],
                    'function': 'source ip address'
                }
            ]
        )

    @classmethod
    def _normalized_type_region(cls):
        return NormalizedType(
            'test_log_type',
            'region',
            [
                {
                    'path': ['region'],
                    'function': 'AWS region'
                },
                {
                    'path': ['detail', 'awsRegion'],
                    'function': 'AWS region'
                }
            ]
        )

    @classmethod
    def _normalized_type_account(cls):
        return NormalizedType('test_log_type', 'account', ['account'])

    @classmethod
    def _normalized_type_user_identity(cls):
        return NormalizedType(
            'test_log_type',
            'user_identity',
            [
                {
                    'path': ['detail', 'userIdentity', 'userName'],
                    'function': 'User name'
                },
                {
                    'path': ['detail', 'userIdentity', 'invokedBy'],
                    'function': 'Service name'
                }
            ]
        )

    @patch('uuid.uuid4', Mock(return_value=MOCK_RECORD_ID))
    def test_match_types(self):
        """Normalizer - Match Types"""
        normalized_types = {
            'region': self._normalized_type_region(),
            'account': self._normalized_type_account(),
            'ipv4': self._normalized_type_ip()
        }
        expected_results = {
            'streamalert_record_id': MOCK_RECORD_ID,
            'account': [
                {
                    'values': ['123456'],
                    'function': None
                }
            ],
            'ipv4': [
                {
                    'values': ['1.1.1.3'],
                    'function': 'source ip address'
                },
                {
                    'values': ['1.1.1.2'],
                    'function': 'source ip address'
                }
            ],
            'region': [
                {
                    'values': ['region_name'],
                    'function': 'AWS region'
                },
                {
                    'values': ['region_name'],
                    'function': 'AWS region'
                }
            ]
        }

        results = Normalizer.match_types(self._test_record(), normalized_types)
        assert results == expected_results

    @patch('uuid.uuid4', Mock(return_value=MOCK_RECORD_ID))
    def test_match_types_multiple(self):
        """Normalizer - Match Types, Mutiple Sub-keys"""
        normalized_types = {
            'account': self._normalized_type_account(),
            'ipv4': self._normalized_type_ip(),
            'region': self._normalized_type_region(),
            'user_identity': self._normalized_type_user_identity()
        }
        expected_results = {
            'streamalert_record_id': MOCK_RECORD_ID,
            'account': [
                {
                    'values': ['123456'],
                    'function': None
                }
            ],
            'ipv4': [
                {
                    'values': ['1.1.1.3'],
                    'function': 'source ip address'
                },
                {
                    'values': ['1.1.1.2'],
                    'function': 'source ip address'
                }
            ],
            'region': [
                {
                    'values': ['region_name'],
                    'function': 'AWS region'
                },
                {
                    'values': ['region_name'],
                    'function': 'AWS region'
                }
            ],
            'user_identity': [
                {
                    'values': ['Alice'],
                    'function': 'User name'
                },
                {
                    'values': ['signin.amazonaws.com'],
                    'function': 'Service name'
                }
            ]
        }

        results = Normalizer.match_types(self._test_record(), normalized_types)
        assert results == expected_results

    @patch('uuid.uuid4', Mock(return_value=MOCK_RECORD_ID))
    def test_normalize(self):
        """Normalizer - Normalize"""
        log_type = 'cloudtrail'
        Normalizer._types_config = {
            log_type: {
                'region': self._normalized_type_region(),
                'ipv4': self._normalized_type_ip()
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
            'streamalert_normalization': {
                'streamalert_record_id': MOCK_RECORD_ID,
                'region': [
                    {
                        'values': ['region_name'],
                        'function': 'AWS region'
                    },
                    {
                        'values': ['region_name'],
                        'function': 'AWS region'
                    }
                ],
                'ipv4': [
                    {
                        'values': ['1.1.1.3'],
                        'function': 'source ip address'
                    },
                    {
                        'values': ['1.1.1.2'],
                        'function': 'source ip address'
                    }
                ]
            }
        }

        assert record == expected_record

    @patch('uuid.uuid4', Mock(return_value=MOCK_RECORD_ID))
    def test_normalize_corner_case(self):
        """Normalizer - Normalize - Corner Case"""
        log_type = 'cloudtrail'
        Normalizer._types_config = {
            log_type: {
                'normalized_key': NormalizedType(
                    log_type,
                    'normalized_key',
                    ['original_key', 'original_key']
                ),
                'account': self._normalized_type_account()
            }
        }
        record = {
            'unrelated_key': 'foobar',
            'original_key': {
                'original_key': 'fizzbuzz',
            }
        }
        Normalizer.normalize(record, log_type)

        expected_record = {
            'unrelated_key': 'foobar',
            'original_key': {
                'original_key': 'fizzbuzz',
            },
            'streamalert_normalization': {
                'streamalert_record_id': MOCK_RECORD_ID,
                'normalized_key': [
                    {
                        'values': ['fizzbuzz'],
                        'function': None
                    }
                ]
            }
        }

        assert record == expected_record

    @patch('logging.Logger.debug')
    def test_normalize_none_defined(self, log_mock):
        """Normalizer - Normalize, No Types Defined"""
        log_type = 'cloudtrail'
        Normalizer._types_config = {}
        Normalizer.normalize(self._test_record(), log_type)
        log_mock.assert_called_with('No normalized types defined for log type: %s', log_type)

    @patch('uuid.uuid4', Mock(return_value=MOCK_RECORD_ID))
    def test_key_does_not_exist(self):
        """Normalizer - Normalize, Key Does Not Exist"""
        test_record = {
            'accountId': 123456,
            'region': 'region_name'
        }

        normalized_types = {
            'region': self._normalized_type_region(),
            'account': NormalizedType('test_log_type', 'account', ['accountId']),
            # There is no IP value in record, so normalization should not include this
            'ipv4': self._normalized_type_ip()
        }
        expected_results = {
            'streamalert_record_id': MOCK_RECORD_ID,
            'account': [
                {
                    'values': ['123456'],
                    'function': None
                }
            ],
            'region': [
                {
                    'values': ['region_name'],
                    'function': 'AWS region'
                }
            ]
        }

        results = Normalizer.match_types(test_record, normalized_types)
        assert results == expected_results

    @patch('uuid.uuid4', Mock(return_value=MOCK_RECORD_ID))
    def test_empty_value(self):
        """Normalizer - Normalize, Empty Value"""
        test_record = {
            'account': 123456,
            'region': ''  # This value is empty so should not be stored
        }

        normalized_types = {
            'region': self._normalized_type_region(),
            'account': self._normalized_type_account(),
            'ipv4': self._normalized_type_ip()
        }
        expected_results = {
            'streamalert_record_id': MOCK_RECORD_ID,
            'account': [
                {
                    'values': ['123456'],
                    'function': None
                }
            ]
        }

        results = Normalizer.match_types(test_record, normalized_types)
        assert results == expected_results

    def test_get_values_for_normalized_type(self):
        """Normalizer - Get Values for Normalized Type"""
        expected_result = {'1.1.1.3'}
        record = {
            'sourceIPAddress': '1.1.1.3',
            'streamalert_normalization': {
                'ip_v4': [
                    {
                        'values': expected_result,
                        'function': None
                    }
                ],
            }
        }

        assert Normalizer.get_values_for_normalized_type(record, 'ip_v4') == expected_result

    def test_get_values_for_normalized_type_none(self):
        """Normalizer - Get Values for Normalized Type, None"""
        record = {
            'sourceIPAddress': '1.1.1.3',
            'streamalert_normalization': {}
        }

        assert Normalizer.get_values_for_normalized_type(record, 'ip_v4') == set()

    def test_load_from_config_exist_types_config(self):
        """Normalizer - Load normalized_types from conf when it was loaded previously"""
        Normalizer._types_config = {'normalized_type1': {}}
        assert Normalizer.load_from_config({'foo': 'bar'}) == Normalizer

    def test_load_from_config(self):
        """Normalizer - Load From Config"""
        config = {
            'logs': {
                'cloudtrail': {
                    'schema': {},
                    'configuration': {
                        'normalization': {
                            'region': ['path', 'to', 'awsRegion'],
                            'sourceAccount': ['path', 'to', 'accountId']
                        }
                    }
                }
            }
        }
        normalizer = Normalizer.load_from_config(config)
        expected_config = {
            'cloudtrail': {
                'region': NormalizedType('cloudtrail', 'region', ['path', 'to', 'awsRegion']),
                'sourceAccount': NormalizedType(
                    'cloudtrail', 'sourceAccount', ['path', 'to', 'accountId']
                )
            }
        }
        assert normalizer == Normalizer
        assert normalizer._types_config == expected_config

    def test_load_from_config_empty(self):
        """Normalizer - Load From Config, Empty"""
        normalizer = Normalizer.load_from_config({})
        assert normalizer == Normalizer
        assert normalizer._types_config is None

    def test_load_from_config_from_log_conf(self):
        """Normalizer - Load normalization config from "logs" field in the config"""
        config = {
            'logs': {
                'cloudwatch:events': {
                    'schema': {
                        'account': 'string',
                        'source': 'string',
                        'key': 'string'
                    },
                    'parser': 'json',
                    'configuration': {
                        'normalization': {
                            'event_name': ['detail', 'eventName'],
                            'region': [
                                {
                                    'path': ['region'],
                                    'function': 'aws region information'
                                },
                                {
                                    'path': ['detail', 'awsRegion'],
                                    'function': 'aws region information'
                                }
                            ],
                            'ip_address': [
                                {
                                    'path': ['detail', 'sourceIPAddress'],
                                    'function': 'source ip address'
                                }
                            ]
                        }
                    }
                }
            }
        }

        expected_config = {
            'cloudwatch:events': {
                'event_name': NormalizedType(
                    'cloudwatch:events', 'event_name', ['detail', 'eventName']
                ),
                'region': NormalizedType(
                    'cloudwatch:events',
                    'region',
                    [
                        {
                            'path': ['region'],
                            'function': 'aws region information'
                        },
                        {
                            'path': ['detail', 'awsRegion'],
                            'function': 'aws region information'
                        }
                    ]
                ),
                'ip_address': NormalizedType(
                    'cloudwatch:events',
                    'ip_address',
                    [
                        {
                            'path': ['detail', 'sourceIPAddress'],
                            'function': 'source ip address'
                        }
                    ]
                )
            }
        }

        normalizer = Normalizer.load_from_config(config)
        assert normalizer == Normalizer
        assert normalizer._types_config == expected_config

    def test_load_from_config_deprecate_normalized_types(self):
        """Normalizer - Load normalization config and deprecate conf/normalized_types.json
        """
        config = {
            'logs': {
                'cloudwatch:events': {
                    'schema': {
                        'account': 'string',
                        'source': 'string',
                        'key': 'string'
                    },
                    'parser': 'json',
                    'configuration': {
                        'normalization': {
                            'ip_address': [
                                {
                                    'path': ['path', 'to', 'sourceIPAddress'],
                                    'function': 'source ip address'
                                }
                            ]
                        }
                    }
                },
                'other_log_type': {}
            },
            'normalized_types': {
                'cloudwatch': {
                    'region': ['region', 'awsRegion'],
                    'sourceAccount': ['account', 'accountId']
                }
            }
        }
        expected_config = {
            'cloudwatch:events': {
                'ip_address': NormalizedType(
                    'cloudwatch:events',
                    'ip_address',
                    [
                        {
                            'path': ['path', 'to', 'sourceIPAddress'],
                            'function': 'source ip address'
                        }
                    ]
                )
            }
        }

        normalizer = Normalizer.load_from_config(config)
        assert normalizer == Normalizer
        assert normalizer._types_config == expected_config

    def test_load_from_config_error(self):
        """Normalizer - Load normalization config raises ConfigError
        """
        config = {
            'logs': {
                'cloudwatch:events': {
                    'schema': {
                        'account': 'string',
                        'source': 'string',
                        'key': 'string'
                    },
                    'parser': 'json',
                    'configuration': {
                        'normalization': {
                            'foo': 'bar'
                        }
                    }
                }
            }
        }
        pytest.raises(ConfigError, Normalizer.load_from_config, config)

        config = {
            'logs': {
                'cloudwatch:events': {
                    'schema': {
                        'account': 'string',
                        'source': 'string',
                        'key': 'string'
                    },
                    'parser': 'json',
                    'configuration': {
                        'normalization': {
                            'ip_address': {
                                'path': ['detail', 'sourceIPAddress'],
                                'function': 'source ip address'
                            }
                        }
                    }
                },
                'other_log_type': {}
            }
        }
        pytest.raises(ConfigError, Normalizer.load_from_config, config)

    @patch('uuid.uuid4', Mock(return_value=MOCK_RECORD_ID))
    def test_load_from_config_with_flag(self):
        """Normalizer - Load From Config with send_to_artifacts flag"""
        config = {
            'logs': {
                'cloudwatch:flow_logs': {
                    'schema': {
                        'source': 'string',
                        'destination': 'string',
                        'destport': 'string'
                    },
                    'configuration': {
                        'normalization': {
                            'ip_address': [
                                {
                                    'path': ['destination'],
                                    'function': 'Destination IP addresses'
                                }
                            ],
                            'port': [
                                {
                                    'path': ['destport'],
                                    'function': 'Destination port number',
                                    'send_to_artifacts': False
                                }
                            ]
                        }
                    }
                }
            }
        }
        normalizer = Normalizer.load_from_config(config)

        record = {
            'source': '1.1.1.2',
            'destination': '2.2.2.2',
            'destport': '54321'
        }

        normalizer.normalize(record, 'cloudwatch:flow_logs')

        expect_result = {
            'source': '1.1.1.2',
            'destination': '2.2.2.2',
            'destport': '54321',
            'streamalert_normalization': {
                'streamalert_record_id': MOCK_RECORD_ID,
                'ip_address': [
                    {
                        'values': ['2.2.2.2'],
                        'function': 'Destination IP addresses'
                    }
                ],
                'port': [
                    {
                        'values': ['54321'],
                        'function': 'Destination port number',
                        'send_to_artifacts': False
                    }
                ]
            }
        }

        assert record == expect_result

    @patch('uuid.uuid4', Mock(return_value=MOCK_RECORD_ID))
    def test_normalize_condition(self):
        """Normalizer - Test normalization when condition applied"""
        log_type = 'cloudtrail'

        region = NormalizedType(
            'test_log_type',
            'region',
            [
                {
                    'path': ['region'],
                    'function': 'AWS region'
                },
                {
                    'path': ['detail', 'awsRegion'],
                    'function': 'AWS region',
                    'condition': {
                        'path': ['detail', 'userIdentity', 'userName'],
                        'not_in': ['alice', 'bob']
                    }
                }
            ]
        )

        ipv4 = NormalizedType(
            'test_log_type',
            'ip_address',
            [
                {
                    'path': ['sourceIPAddress'],
                    'function': 'source ip address',
                    'condition': {
                        'path': ['account'],
                        'is': '123456'
                    }
                },
                {
                    'path': ['detail', 'source'],
                    'function': 'source ip address',
                    'condition': {
                        'path': ['account'],
                        'is_not': '123456'
                    }
                }
            ]
        )

        Normalizer._types_config = {
            log_type: {
                'region': region,
                'ipv4': ipv4
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
            'streamalert_normalization': {
                'streamalert_record_id': MOCK_RECORD_ID,
                'region': [
                    {
                        'values': ['region_name'],
                        'function': 'AWS region'
                    }
                ],
                'ipv4': [
                    {
                        'values': ['1.1.1.3'],
                        'function': 'source ip address'
                    }
                ]
            }
        }
        assert record == expected_record

    def test_match_condition(self):
        """Normalizer - Test match condition with different conditions"""
        record = self._test_record()

        condition = {
            'path': ['account'],
            'is': '123456'
        }
        assert Normalizer._match_condition(record, condition)

        condition = {
            'path': ['account'],
            'is_not': '123456'
        }
        assert not Normalizer._match_condition(record, condition)

        condition = {
            'path': ['detail', 'awsRegion'],
            'contains': 'region'
        }
        assert Normalizer._match_condition(record, condition)

        condition = {
            'path': ['detail', 'awsRegion'],
            'contains': 'not_region'
        }
        assert not Normalizer._match_condition(record, condition)

        condition = {
            'path': ['detail', 'userIdentity', 'userName'],
            'not_contains': 'alice'
        }
        assert not Normalizer._match_condition(record, condition)

        condition = {
            'path': ['sourceIPAddress'],
            'in': ['1.1.1.2', '1.1.1.3']
        }
        assert Normalizer._match_condition(record, condition)

        condition = {
            'path': ['sourceIPAddress'],
            'not_in': ['1.1.1.2', '1.1.1.3']
        }
        assert not Normalizer._match_condition(record, condition)

        # Only support extract one condition. The result is not quaranteed if multiple conditions
        # configured. In this test case, it is because 'not_in' condition is checked before
        # 'contains'
        condition = {
            'path': ['detail', 'userIdentity', 'invokedBy'],
            'contains': 'amazonaws.com',
            'not_in': ['signin.amazonaws.com', 's3.amazonaws.com']
        }
        assert not Normalizer._match_condition(record, condition)

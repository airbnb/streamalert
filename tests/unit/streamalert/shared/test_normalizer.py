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
from mock import patch
from nose.tools import assert_equal, assert_raises

from streamalert.shared.exceptions import ConfigError
from streamalert.shared.normalize import Normalizer


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

    def test_match_types(self):
        """Normalizer - Match Types"""
        normalized_types = {
            'region': {
                'fields': ['region', 'awsRegion']
            },
            'sourceAccount': {
                'fields': ['account', 'accountId']
            },
            'ipv4': {
                'fields': ['destination', 'source', 'sourceIPAddress']
            }
        }
        expected_results = {
            'sourceAccount': {
                'values': [123456],
                'function': None
            },
            'ipv4': {
                'values': ['1.1.1.2', '1.1.1.3'],
                'function': None
            },
            'region': {
                'values': ['region_name'],
                'function': None
            }
        }

        results = Normalizer.match_types(self._test_record(), normalized_types)
        assert_equal(results, expected_results)

    def test_match_types_multiple(self):
        """Normalizer - Match Types, Mutiple Sub-keys"""
        normalized_types = {
            'account': {
                'fields': ['account']
            },
            'region': {
                'fields': ['region', 'awsRegion']
            },
            'ipv4': {
                'fields': ['destination', 'source', 'sourceIPAddress']
            },
            'userName': {
                'fields': ['userName', 'owner', 'invokedBy']
            }
        }
        expected_results = {
            'account': {
                'values': [123456],
                'function': None
            },
            'ipv4': {
                'values': ['1.1.1.2', '1.1.1.3'],
                'function': None
            },
            'region': {
                'values': ['region_name'],
                'function': None
            },
            'userName': {
                'values': ['Alice', 'signin.amazonaws.com'],
                'function': None
            }
        }

        results = Normalizer.match_types(self._test_record(), normalized_types)
        assert_equal(results, expected_results)

    def test_match_types_list(self):
        """Normalizer - Match Types, List of Values"""
        normalized_types = {
            'ipv4': {
                'fields': ['sourceIPAddress']
            },
        }
        expected_results = {
            'ipv4': {
                'values': ['1.1.1.2', '1.1.1.3'],
                'function': None
            }
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
                    'fields': ['region', 'awsRegion']
                },
                'sourceAccount': {
                    'fields': ['account', 'accountId']
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
                'region': {
                    'values': ['region_name'],
                    'function': None
                },
                'sourceAccount': {
                    'values': [123456],
                    'function': None
                }
            }
        }

        assert_equal(record, expected_record)

    def test_normalize_corner_case(self):
        """Normalizer - Normalize - Corner Case"""
        log_type = 'cloudtrail'
        Normalizer._types_config = {
            log_type: {
                'normalized_key': {
                    'fields': ['normalized_key', 'original_key']
                },
                'sourceAccount': {
                    'fields': ['account', 'accountId']
                }
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
            'streamalert:normalization': {
                'normalized_key': {
                    'values': ['fizzbuzz'],
                    'function': None
                }
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
            'region': {
                'fields': ['region', 'awsRegion']
            },
            'sourceAccount': {
                'fields': ['account', 'accountId']
            },
            # There is no IP value in record, so normalization should not include this
            'ipv4': {
                'fields': ['sourceIPAddress']
            }
        }
        expected_results = {
            'sourceAccount': {
                'values': [123456],
                'function': None
            },
            'region': {
                'values': ['region_name'],
                'function': None
            }
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
            'region': {
                'fields': ['region', 'awsRegion']
            },
            'sourceAccount': {
                'fields': ['account', 'accountId']
            },
            'ipv4': {
                'fields': ['sourceIPAddress']
            }
        }
        expected_results = {
            'sourceAccount': {
                'values': [123456],
                'function': None
            }
        }

        results = Normalizer.match_types(test_record, normalized_types)
        assert_equal(results, expected_results)

    def test_get_values_for_normalized_type(self):
        """Normalizer - Get Values for Normalized Type"""
        expected_result = {'1.1.1.3'}
        record = {
            'sourceIPAddress': '1.1.1.3',
            'streamalert:normalization': {
                'ip_v4': {
                    'values': expected_result,
                    'function': None
                },
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

    def test_load_from_config_exist_types_config(self):
        """Normalizer - Load normalized_types from conf when it was loaded previously"""
        Normalizer._types_config = {'normalized_type1': {}}
        assert_equal(Normalizer.load_from_config({'foo': 'bar'}), Normalizer)

    def test_load_from_config(self):
        """Normalizer - Load From Config"""
        config = {
            'logs': {
                'cloudtrail': {}
            },
            'normalized_types': {
                'cloudtrail': {
                    'region': {
                        'fields': ['region', 'awsRegion']
                    },
                    'sourceAccount': {
                        'fields': ['account', 'accountId']
                    }
                }
            }
        }
        normalizer = Normalizer.load_from_config(config)
        expected_config = {
            'cloudtrail': {
                'region': {
                    'fields': ['region', 'awsRegion']
                },
                'sourceAccount': {
                    'fields': ['account', 'accountId']
                }
            }
        }
        assert_equal(normalizer, Normalizer)
        assert_equal(normalizer._types_config, expected_config)

    def test_load_from_config_empty(self):
        """Normalizer - Load From Config, Empty"""
        normalizer = Normalizer.load_from_config({})
        assert_equal(normalizer, Normalizer)
        assert_equal(normalizer._types_config, None)

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
                            'region': {
                                'fields': [
                                    'region',
                                    'awsRegion'
                                ]
                            },
                            'sourceAccount': [
                                'account',
                                'accountId'
                            ],
                            'sourceAddress': {
                                'fields': [
                                    'source',
                                    'sourceIPAddress'
                                ],
                                'function': 'source ip address'
                            }
                        }
                    }
                }
            }
        }

        expected_config = {
            'cloudwatch:events': {
                'region': {
                    'fields': [
                        'region',
                        'awsRegion'
                    ]
                },
                'sourceAccount': {
                    'fields': [
                        'account',
                        'accountId'
                    ]
                },
                'sourceAddress': {
                    'fields': [
                        'source',
                        'sourceIPAddress'
                    ],
                    'function': 'source ip address'
                }
            }
        }

        normalizer = Normalizer.load_from_config(config)
        assert_equal(normalizer, Normalizer)
        assert_equal(normalizer._types_config, expected_config)

    def test_load_from_config_merge(self):
        """Normalizer - Load normalization config by merging "normalization" and "logs" fields in
        the config.
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
                            'sourceAccount': [
                                'account',
                                'accountId'
                            ],
                            'sourceAddress': {
                                'fields': [
                                    'source',
                                    'sourceIPAddress'
                                ],
                                'function': 'source ip address'
                            }
                        }
                    }
                },
                'other_log_type': {}
            },
            'normalized_types': {
                'cloudwatch': {
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
            'cloudwatch:events': {
                'region': {
                    'fields': [
                        'region',
                        'awsRegion'
                    ]
                },
                'sourceAccount': {
                    'fields': [
                        'account',
                        'accountId'
                    ]
                },
                'sourceAddress': {
                    'fields': [
                        'source',
                        'sourceIPAddress'
                    ],
                    'function': 'source ip address'
                }
            }
        }
        assert_equal(normalizer, Normalizer)
        assert_equal(normalizer._types_config, expected_config)

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
        assert_raises(ConfigError, Normalizer.load_from_config, config)

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

from botocore.exceptions import ClientError, ParamValidationError
from netaddr import IPNetwork

from streamalert.rules_engine.threat_intel import ThreatIntel


# Without this time.sleep patch, backoff performs sleep
# operations and drastically slows down testing
@patch('time.sleep', Mock())
class TestThreatIntel:
    """Tests for ThreatIntel"""
    # pylint: disable=attribute-defined-outside-init,protected-access,no-self-use

    def setup(self):
        """ThreatIntel - Setup"""
        with patch('boto3.client'):
            self._threat_intel = ThreatIntel.load_from_config(self._default_config)

    def teardown(self):
        """ThreatIntel - Teardown"""
        ThreatIntel._client = None

    @property
    def _default_config(self):
        return {
            'threat_intel': {
                'dynamodb_table_name': 'table_name',
                'enabled': True,
                'excluded_iocs': {
                    'domain': {
                        'not.evil.com': {
                            'comment': 'not an evil domain'
                        }
                    }
                },
                'normalized_ioc_types': {
                    'domain': [
                        'destinationDomain'
                    ],
                    'ip': [
                        'sourceAddress',
                        'destinationAddress'
                    ],
                    'md5': [
                        'fileHash'
                    ]
                }
            },
            'clusters': {
                'prod': {
                    'enable_threat_intel': True
                }
            }
        }

    @property
    def _sample_payload(self):
        return {
            'record': {
                'account': 12345,
                'region': 'us-east-1',
                'detail': {
                    'eventName': 'ConsoleLogin',
                    'userIdentity': {
                        'userName': 'alice',
                        'accountId': '12345'
                    },
                    'sourceIPAddress': '1.1.1.2',
                    'recipientAccountId': '12345'
                },
                'source': '1.1.1.2',
                'streamalert_normalization': {
                    'sourceAddress': {'1.1.1.2'},
                    'userName': {'alice'}
                }
            }
        }

    def test_exceptions_to_giveup(self):
        """ThreatIntel - Exceptions to Giveup"""
        err = Mock(
            response={'Error': {'Code': 'ResourceNotFoundException'}}
        )

        result = ThreatIntel._exceptions_to_giveup(err)
        assert result

    def test_threat_detection(self):
        """ThreatIntel - Threat Detection"""
        payloads = [self._sample_payload]

        expected_result = {
            'account': 12345,
            'region': 'us-east-1',
            'detail': {
                'eventName': 'ConsoleLogin',
                'userIdentity': {
                    'userName': 'alice',
                    'accountId': '12345'
                },
                'sourceIPAddress': '1.1.1.2',
                'recipientAccountId': '12345'
            },
            'source': '1.1.1.2',
            'streamalert_normalization': {
                'sourceAddress': {'1.1.1.2'},
                'userName': {'alice'}
            },
            'streamalert:ioc': {
                'ip': {'1.1.1.2'}
            }
        }

        with patch.object(self._threat_intel, '_process_ioc_values') as process_mock:
            process_mock.return_value = [{'ioc_value': '1.1.1.2', 'sub_type': 'mal_ip'}]
            self._threat_intel.threat_detection(payloads)
            assert payloads[0]['record'] == expected_result

    def test_threat_detection_no_iocs(self):
        """ThreatIntel - Threat Detection, No IOCs"""
        payloads = [self._sample_payload]

        expected_result = {
            'account': 12345,
            'region': 'us-east-1',
            'detail': {
                'eventName': 'ConsoleLogin',
                'userIdentity': {
                    'userName': 'alice',
                    'accountId': '12345'
                },
                'sourceIPAddress': '1.1.1.2',
                'recipientAccountId': '12345'
            },
            'source': '1.1.1.2',
            'streamalert_normalization': {
                'sourceAddress': {'1.1.1.2'},
                'userName': {'alice'}
            }
        }

        with patch.object(self._threat_intel, '_process_ioc_values') as process_mock:
            process_mock.return_value = []
            self._threat_intel.threat_detection(payloads)
            assert payloads[0]['record'] == expected_result

    def test_insert_ioc_info(self):
        """ThreatIntel - Insert IOC Info"""
        record = {
            'key': 'value'
        }

        ioc_type = 'ip'
        ioc_value = 'ioc_value'
        expected_result = {
            'key': 'value',
            'streamalert:ioc': {
                ioc_type: {ioc_value}
            }
        }

        ThreatIntel._insert_ioc_info(record, ioc_type, ioc_value)
        assert record == expected_result

    def test_insert_ioc_info_existing(self):
        """ThreatIntel - Insert IOC Info, With Existing"""
        ioc_type = 'ip'
        existing_value = 'existing_value'
        record = {
            'key': 'value',
            'streamalert:ioc': {
                ioc_type: {existing_value}
            }
        }

        new_value = 'new_value'
        expected_result = {
            'key': 'value',
            'streamalert:ioc': {
                ioc_type: {existing_value, new_value}
            }
        }

        ThreatIntel._insert_ioc_info(record, ioc_type, new_value)

        assert record == expected_result

    def test_process_ioc_values(self):
        """ThreatIntel - Process IOC Values"""
        potential_iocs = ['1.1.1.1', '2.2.2.2']
        with patch.object(self._threat_intel, '_query') as query_mock:
            query_mock.side_effect = [['2.2.2.2']]

            expected_result = ['2.2.2.2']

            result = list(self._threat_intel._process_ioc_values(potential_iocs))
            query_mock.assert_called_with(set(potential_iocs))
            assert result == expected_result

    @patch('logging.Logger.exception')
    def testg_client_error(self, log_mock):
        """ThreatIntel - Process IOC Values, ClientError"""
        potential_iocs = ['1.1.1.1', '2.2.2.2']
        with patch.object(self._threat_intel, '_query') as query_mock:
            query_mock.side_effect = ClientError({'Error': {'Code': 10}}, 'BadRequest')

            result = list(self._threat_intel._process_ioc_values(potential_iocs))
            assert not result
            log_mock.assert_called_with('An error occurred while querying dynamodb table')

    @patch('logging.Logger.exception')
    def test_process_ioc_values_parameter_error(self, log_mock):
        """ThreatIntel - Process IOC Values, ParamValidationError"""
        potential_iocs = ['1.1.1.1', '2.2.2.2']
        with patch.object(self._threat_intel, '_query') as query_mock:
            query_mock.side_effect = ParamValidationError(report='BadParams')

            result = list(self._threat_intel._process_ioc_values(potential_iocs))
            assert not result
            log_mock.assert_called_with('An error occurred while querying dynamodb table')

    def test_segment(self):
        """ThreatIntel - Segment"""
        expected_result = [
            set(range(100)),
            set(range(100, 120))
        ]

        result = list(ThreatIntel._segment(list(range(120))))
        assert result == expected_result

    def test_query_client_error(self):
        """ThreatIntel - Query, ClientError"""
        query_values = {
            '1.1.1.1'
        }
        self._threat_intel._dynamodb.batch_get_item.side_effect = [
            # Raise a ClientError on first call
            ClientError({'Error': {'Code': 10}}, 'BadRequest'),
            {
                'UnprocessedKeys': {},
                'Responses': {
                    'table_name': [
                        {
                            'ioc_value': {
                                'S': '1.1.1.1',
                            },
                            'sub_type': {
                                'S': 'mal_ip'
                            }
                        }
                    ]
                }
            }
        ]

        expected_result = [
            {
                'ioc_value': '1.1.1.1',
                'sub_type': 'mal_ip'
            }
        ]

        result = self._threat_intel._query(query_values)
        assert self._threat_intel._dynamodb.batch_get_item.call_count == 2

        assert result == expected_result

    def test_query_unprocessed_keys(self):
        """ThreatIntel - Query, With Unprocessed Keys"""
        query_values = {
            '1.1.1.1',
            '2.2.2.2',
            '01d0a70299bb8985caad5107dbcf138e'
        }

        self._threat_intel._dynamodb.batch_get_item.side_effect = [
            {
                'UnprocessedKeys': {  # UnprocessedKeys will cause this to retry once
                    'table_name': {
                        'Keys': [
                            {
                                'ioc_value': {
                                    'S': '2.2.2.2'
                                }
                            }
                        ]
                    }
                },
                'Responses': {
                    'table_name': [
                        {
                            'ioc_value': {
                                'S': '1.1.1.1',
                            },
                            'sub_type': {
                                'S': 'mal_ip'
                            }
                        },
                        {
                            'ioc_value': {
                                'S': '01d0a70299bb8985caad5107dbcf138e',
                            },
                            'sub_type': {
                                'S': 'mal_md5'
                            }
                        }
                    ]
                }
            },
            {
                'UnprocessedKeys': {},
                'Responses': {
                    'table_name': [
                        {
                            'ioc_value': {
                                'S': '2.2.2.2',
                            },
                            'sub_type': {
                                'S': 'mal_ip'
                            }
                        }
                    ]
                }
            }
        ]

        expected_result = [
            {
                'ioc_value': '1.1.1.1',
                'sub_type': 'mal_ip'
            },
            {
                'ioc_value': '01d0a70299bb8985caad5107dbcf138e',
                'sub_type': 'mal_md5'
            },
            {
                'ioc_value': '2.2.2.2',
                'sub_type': 'mal_ip'
            }
        ]

        result = self._threat_intel._query(query_values)
        assert self._threat_intel._dynamodb.batch_get_item.call_count == 2

        assert result == expected_result

    def test_remove_processed_keys(self):
        """ThreatIntel - Remove Unprocessed Keys"""
        query_values = {
            '1.1.1.1',
            '2.2.2.2',
            '09bb8985ca0a702907dbcfad511d138e',
            '02907dbcfad38e511d109bb8985ca0a7'
        }

        unprocesed_keys = [
            {
                'ioc_value': {
                    'S': '2.2.2.2'
                },
                'sub_type': {
                    'S': 'mal_ip'
                }
            },
            {
                'ioc_value': {
                    'S': '09bb8985ca0a702907dbcfad511d138e'
                },
                'sub_type': {
                    'S': 'mal_md5'
                }
            }
        ]

        expected_result = {
            '2.2.2.2',
            '09bb8985ca0a702907dbcfad511d138e'
        }

        ThreatIntel._remove_processed_keys(query_values, unprocesed_keys)
        assert query_values == expected_result

    def test_deserialize(self):
        """ThreatIntel - Deserialize"""
        data = [
            {
                'ioc_value': {
                    'S': '09bb8985ca0a702907dbcfad511d138e'
                },
                'sub_type': {
                    'S': 'mal_md5'
                }
            }
        ]

        expected_result = [
            {
                'ioc_value': '09bb8985ca0a702907dbcfad511d138e',
                'sub_type': 'mal_md5'
            }
        ]

        result = list(ThreatIntel._deserialize(data))
        assert result == expected_result

    def test_is_excluded_ioc(self):
        """ThreatIntel - Is Excluded IOC"""
        assert self._threat_intel._is_excluded_ioc('domain', 'not.evil.com')

    def test_is_excluded_ioc_ip(self):
        """ThreatIntel - Is Excluded IOC, IP"""
        self._threat_intel._excluded_iocs['ip'] = {
            IPNetwork('1.2.3.0/28')
        }
        assert self._threat_intel._is_excluded_ioc('ip', '1.2.3.20') == False
        assert self._threat_intel._is_excluded_ioc('ip', '1.2.3.15')

    def test_extract_ioc_values(self):
        """ThreatIntel - Extract IOC Values"""
        payloads = [self._sample_payload]
        expected_result = {
            '1.1.1.2': [
                (
                    'ip',
                    payloads[0]['record']
                )
            ]
        }
        result = self._threat_intel._extract_ioc_values(payloads)
        assert result == expected_result

    def test_extract_ioc_values_excluded(self):
        """ThreatIntel - Extract IOC Values, With Excluded"""
        payload = self._sample_payload
        self._threat_intel._excluded_iocs['ip'] = {
            IPNetwork('1.1.1.2')
        }
        result = self._threat_intel._extract_ioc_values([payload])
        assert result == {}

    def test_setup_excluded_iocs(self):
        """ThreatIntel - Setup Excluded IOCs"""
        excluded_iocs = {
            'md5': {
                'feca1deadbeefcafebeadbeefcafebee': {
                    'comment': 'not malicious'
                }
            }
        }
        expected_result = {
            'md5': {
                'feca1deadbeefcafebeadbeefcafebee'
            }
        }
        result = ThreatIntel._setup_excluded_iocs(excluded_iocs)
        assert result == expected_result

    def test_setup_excluded_iocs_ip(self):
        """ThreatIntel - Setup Excluded IOCs, With IPs"""
        excluded_iocs = {
            'ip': {
                '10.0.0.0/8': {
                    'comment': 'RFC1918'
                }
            },
            'md5': {
                'feca1deadbeefcafebeadbeefcafebee': {
                    'comment': 'not malicious'
                }
            }
        }
        expected_result = {
            'ip': {
                IPNetwork('10.0.0.0/8')
            },
            'md5': {
                'feca1deadbeefcafebeadbeefcafebee'
            }
        }
        result = ThreatIntel._setup_excluded_iocs(excluded_iocs)
        assert result == expected_result

    def test_load_from_config_empty(self):
        """ThreatIntel - Load From Config, Empty"""
        assert ThreatIntel.load_from_config({}) is None

    def test_load_from_config_disabled(self):
        """ThreatIntel - Load From Config, Disabled"""
        config = {
            'threat_intel': {
                'enabled': False
            }
        }
        assert ThreatIntel.load_from_config(config) is None

    def test_load_from_config_no_clusters(self):
        """ThreatIntel - Load From Config, Clusters Disabled"""
        config = {
            'threat_intel': {
                'enabled': True
            },
            'clusters': {
                'prod': {
                    'enable_threat_intel': False
                }
            }
        }
        assert ThreatIntel.load_from_config(config) is None

    def test_load_from_config(self):
        """ThreatIntel - Load From Config"""
        ti_client = ThreatIntel.load_from_config(self._default_config)

        assert isinstance(ti_client, ThreatIntel)
        assert ti_client._table == 'table_name'
        assert ti_client._enabled_clusters == {'prod'}
        expected_config = {
            'destinationDomain': 'domain',
            'sourceAddress': 'ip',
            'destinationAddress': 'ip',
            'fileHash': 'md5'
        }
        assert ti_client._ioc_config == expected_config
        assert ti_client._excluded_iocs == {'domain': {'not.evil.com'}}

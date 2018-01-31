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
# pylint: disable=protected-access,no-self-use
from botocore.exceptions import ClientError, ParamValidationError
from mock import patch
from nose.tools import (
    assert_equal,
    assert_false,
    assert_is_instance,
    assert_true,
    raises,
)

from stream_alert.rule_processor.config import load_config
from stream_alert.rule_processor.threat_intel import StreamThreatIntel, StreamIoc
from tests.unit.stream_alert_rule_processor.test_helpers import (
    MockDynamoDBClient,
    mock_normalized_records,
)

class TestStreamIoc(object):
    """Test class for StreamIoc which store IOC info"""
    def test_instance_initialization(self):
        """StreamIoc - Test StreamIoc initialization"""
        ioc = StreamIoc()
        assert_equal(ioc.value, None)
        assert_equal(ioc.ioc_type, None)
        assert_equal(ioc.sub_type, None)
        assert_equal(ioc.associated_record, None)
        assert_false(ioc.is_ioc)

        new_ioc = StreamIoc(value='1.1.1.2', ioc_type='ip',
                            associated_record={'foo': 'bar'}, is_ioc=True)
        assert_equal(new_ioc.value, '1.1.1.2')
        assert_equal(new_ioc.ioc_type, 'ip')
        assert_equal(new_ioc.associated_record, {'foo': 'bar'})
        assert_true(new_ioc.is_ioc)

    def test_set_properties(self):
        """StreamIoc - Test setter of class properties"""
        ioc = StreamIoc(value='evil.com', ioc_type='domain',
                        associated_record={'foo': 'bar'}, is_ioc=True)
        ioc.value = 'evil.com'
        assert_equal(ioc.value, 'evil.com')
        ioc.ioc_type = 'test_ioc_type'
        assert_equal(ioc.ioc_type, 'test_ioc_type')
        ioc.associated_record = None
        assert_equal(ioc.associated_record, None)
        ioc.is_ioc = False
        assert_false(ioc.is_ioc)

@patch.object(StreamThreatIntel, 'BACKOFF_MAX_RETRIES', 1)
class TestStreamThreatIntel(object):
    """Test class for StreamThreatIntel"""
    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.config = None
        cls.threat_intel = None

    def setup(self):
        """Setup before each method"""
        # Clear out the cached matchers and rules to avoid conflicts with production code
        self.config = load_config('tests/unit/conf')
        self.config['global']['threat_intel']['enabled'] = True
        self.threat_intel = StreamThreatIntel.load_from_config(self.config)

    def teardown(self):
        StreamThreatIntel._StreamThreatIntel__normalized_types.clear() # pylint: disable=no-member

    @patch('boto3.client')
    def test_threat_detection(self, mock_client):
        """Threat Intel - Test threat_detection method"""
        mock_client.return_value = MockDynamoDBClient()
        records = mock_normalized_records()
        threat_intel = StreamThreatIntel.load_from_config(self.config)

        assert_equal(len(threat_intel.threat_detection(records)), 2)

    @patch('boto3.client')
    def test_threat_detection_with_empty_ioc_value(self, mock_client):
        """Threat Intel - Test threat_detection with record contains empty/duplicated value"""
        records = [
            {
                'account': 12345,
                'region': '123456123456',
                'detail': {
                    'eventName': 'ConsoleLogin',
                    'userIdentity': {
                        'userName': 'alice',
                        'accountId': '12345'
                    },
                    'sourceIPAddress': None,
                    'recipientAccountId': '12345'
                },
                'source': '1.1.1.2',
                'streamalert:normalization': {
                    'sourceAddress': [['detail', 'sourceIPAddress'], ['source']],
                    'usernNme': [['detail', 'userIdentity', 'userName']]
                }
            },
            {
                'domain': 'evil.com',
                'pc_name': 'test-pc',
                'date': 'Dec 1st, 2016',
                'data': 'ABCDEF',
                'streamalert:normalization': {
                    'destinationDomain': [['domain']]
                }
            },
            {
                'domain': 'EVIL.com',
                'pc_name': 'test-pc',
                'date': 'Dec 1st, 2016',
                'data': 'ABCDEF',
                'streamalert:normalization': {
                    'destinationDomain': [['domain']]
                }
            },
        ]
        mock_client.return_value = MockDynamoDBClient()
        threat_intel = StreamThreatIntel.load_from_config(self.config)
        records = mock_normalized_records(records)
        assert_equal(len(threat_intel.threat_detection(records)), 3)

    def test_insert_ioc_info(self):
        """Threat Intel - Insert IOC info to a record"""
        # rec has no IOC info
        rec = {
            'key1': 'foo',
            'key2': 'bar'
        }

        self.threat_intel._insert_ioc_info(rec, 'ip', '1.2.3.4')
        expected_results = {
            "ip": ['1.2.3.4']
        }
        assert_equal(rec['streamalert:ioc'], expected_results)

        # rec has IOC info and new info is duplicated
        rec_with_ioc_info = {
            'key1': 'foo',
            'key2': 'bar',
            'streamalert:ioc': {
                'ip': ['1.2.3.4']
            }
        }

        self.threat_intel._insert_ioc_info(rec_with_ioc_info, 'ip', '1.2.3.4')
        expected_results = {
            "ip": ['1.2.3.4']
        }
        assert_equal(rec_with_ioc_info['streamalert:ioc'], expected_results)

        # rec has IOC info
        rec_with_ioc_info = {
            'key1': 'foo',
            'key2': 'bar',
            'streamalert:ioc': {
                'ip': ['4.3.2.1']
            }
        }

        self.threat_intel._insert_ioc_info(rec_with_ioc_info, 'ip', '1.2.3.4')
        expected_results = {
            "ip": ['4.3.2.1', '1.2.3.4']
        }
        assert_equal(rec_with_ioc_info['streamalert:ioc'], expected_results)

    def test_extract_ioc_from_record(self):
        """Threat Intel - Test extracting values from a record based on normalized keys"""
        records = [{
            'account': 12345,
            'region': '123456123456',
            'detail': {
                'eventType': 'AwsConsoleSignIn',
                'eventName': 'ConsoleLogin',
                'userIdentity': {
                    'userName': 'alice',
                    'type': 'Root',
                    'principalId': '12345',
                },
                'sourceIPAddress': '1.1.1.2',
                'recipientAccountId': '12345'
            },
            'source': '1.1.1.2',
            'streamalert:normalization': {
                'sourceAddress': [['detail', 'sourceIPAddress'], ['source']],
                'usernNme': [['detail', 'userIdentity', 'userName']]
            },
            'id': '12345'
        }]
        records = mock_normalized_records(records)
        for record in records:
            result = self.threat_intel._extract_ioc_from_record(record)
            assert_equal(len(result), 1)
            assert_equal(result[0].value, '1.1.1.2')

        records = [{
            'cb_server': 'cbserver',
            'computer_name': 'DESKTOP-TESTING',
            'direction': 'outbound',
            'domain': 'evil.com',
            'event_type': 'netconn',
            'ipv4': '1.1.1.2',
            'local_ip': '1.1.1.2',
            'local_port': '57347',
            'md5': 'ABCDEF0123456789ABCDEF0123456789',
            'pid': '268',
            'port': '50002',
            'process_guid': '00003a07-0000-010c-01d3-766fd6eee995',
            'process_path': 'bad_actor.exe',
            'protocol': '6',
            'remote_ip': '82.82.82.82',
            'remote_port': '50002',
            'sensor_id': '14855',
            'timestamp': 1515151515,
            'type': 'ingress.event.netconn',
            'streamalert:normalization': {
                'destinationAddress': [['remote_ip']],
                'destinationDomain': [['domain']],
                'fileHash': [['md5']],
                'sourceAddress': [['ipv4'], ['local_ip']]
            }
        }]

        records = mock_normalized_records(records)
        for record in records:
            results = self.threat_intel._extract_ioc_from_record(record)
            assert_equal(len(results), 4)
            assert_equal((results[0].value, results[0].ioc_type), ('1.1.1.2', 'ip'))
            assert_equal((results[1].value, results[1].ioc_type), ('82.82.82.82', 'ip'))
            assert_equal((results[2].value, results[2].ioc_type), ('evil.com', 'domain'))
            assert_equal((results[3].value, results[3].ioc_type),
                         ('abcdef0123456789abcdef0123456789', 'md5'))

    def test_extract_ioc_from_record_with_private_ip(self):
        """Threat Intel - Test extracting values from a record based on normalized keys"""
        records = [
            {
                'account': 12345,
                'region': '123456123456',
                'detail': {
                    'eventType': 'AwsConsoleSignIn',
                    'eventName': 'ConsoleLogin',
                    'userIdentity': {
                        'userName': 'alice',
                        'type': 'Root',
                        'principalId': '12345',
                    },
                    'sourceIPAddress': 'ec2.amazon.com',
                    'recipientAccountId': '12345'
                },
                'source': 'ec2.amazon.com',
                'streamalert:normalization': {
                    'sourceAddress': [['detail', 'sourceIPAddress'], ['source']],
                    'usernNme': [['detail', 'userIdentity', 'userName']]
                },
                'id': '12345'
            },
            {
                'account': 12345,
                'region': '123456123456',
                'detail': {
                    'eventType': 'AwsConsoleSignIn',
                    'eventName': 'ConsoleLogin',
                    'userIdentity': {
                        'userName': 'alice',
                        'type': 'Root',
                        'principalId': '12345',
                    },
                    'sourceIPAddress': '192.168.1.2',
                    'recipientAccountId': '12345'
                },
                'source': '192.168.1.2',
                'streamalert:normalization': {
                    'sourceAddress': [['detail', 'sourceIPAddress'], ['source']],
                    'usernNme': [['detail', 'userIdentity', 'userName']]
                },
                'id': '12345'
            }
        ]
        records = mock_normalized_records(records)
        for record in records:
            result = self.threat_intel._extract_ioc_from_record(record)
            assert_equal(len(result), 0)

    def test_load_from_config(self):
        """Threat Intel - Test load_config method"""
        test_config = {
            'global': {
                'account': {
                    'region': 'us-east-1'
                },
                'threat_intel': {
                    'dynamodb_table': 'test_table_name',
                    'enabled': True
                }
            }
        }

        threat_intel = StreamThreatIntel.load_from_config(test_config)
        assert_true(isinstance(threat_intel, StreamThreatIntel))

        test_config = {
            'global': {
                'account': {
                    'region': 'us-east-1'
                },
                'threat_intel': {
                    'dynamodb_table': 'test_table_name',
                    'enabled': False
                }
            }
        }
        threat_intel = StreamThreatIntel.load_from_config(test_config)
        assert_false(threat_intel)

        test_config = {
            'types': {
                'log_src1': {
                    'normalizedTypeFoo:ioc_foo': ['foo1', 'foo2'],
                    'normalizedTypeBar:ioc_bar': ['bar1', 'bar2']
                },
                'log_src2': {
                    'normalizedTypePing:ioc_ping': ['ping1', 'ping2'],
                    'normalizedTypePong:ioc_pong': ['pong1', 'pong2']
                }
            }
        }
        StreamThreatIntel.load_from_config(test_config)
        expected_result = {
            'log_src1': {
                'normalizedTypeBar': ['bar1', 'bar2'],
                'normalizedTypeFoo': ['foo1', 'foo2']
            },
            'log_src2': {
                'normalizedTypePing': ['ping1', 'ping2'],
                'normalizedTypePong': ['pong1', 'pong2']
            }
        }
        assert_equal(StreamThreatIntel.normalized_type_mapping(), expected_result)

    def test_load_from_config_with_cluster_env(self):
        """Threat Intel - Test load_from_config to read cluster env variable"""
        with patch.dict('os.environ', {'CLUSTER': 'advanced'}):
            config = load_config('tests/unit/conf')
            config['global']['threat_intel']['enabled'] = True
            threat_intel = StreamThreatIntel.load_from_config(config)
            assert_is_instance(threat_intel, StreamThreatIntel)
            assert_equal(config['clusters'].keys(), ['advanced'])

    def test_load_from_config_with_cluster_env_2(self):
        """Threat Intel - Test load_from_config with threat intel disabled in cluster"""
        with patch.dict('os.environ', {'CLUSTER': 'test'}):
            config = load_config('tests/unit/conf')
            config['global']['threat_intel']['enabled'] = True
            threat_intel = StreamThreatIntel.load_from_config(config)
            assert_false(isinstance(threat_intel, StreamThreatIntel))
            assert_equal(config['clusters'].keys(), ['test'])

    def test_process_types_config(self):
        """Threat Intel - Test process_types_config method"""
        test_config = {
            'types': {
                'log_src1': {
                    'normalizedTypeFoo:ioc_foo': ['foo1', 'foo2'],
                    'normalizedTypeBar:ioc_bar': ['bar1', 'bar2'],
                    'normalizedTypePan': ['pan1']
                },
                'log_src2': {
                    'normalizedTypePing:ioc_ping': ['ping1', 'ping2'],
                    'normalizedTypePong:ioc_pong': ['pong1', 'pong2']
                }
            }
        }

        expected_result = {
            'log_src1': {
                'normalizedTypeBar': ['bar1', 'bar2'],
                'normalizedTypeFoo': ['foo1', 'foo2'],
                'normalizedTypePan': ['pan1']
            },
            'log_src2': {
                'normalizedTypePing': ['ping1', 'ping2'],
                'normalizedTypePong': ['pong1', 'pong2']
            }
        }
        StreamThreatIntel._process_types_config(test_config['types'])
        assert_equal(StreamThreatIntel.normalized_type_mapping(), expected_result)

    @patch('stream_alert.rule_processor.threat_intel.LOGGER.info')
    def test_validate_invalid_type_mapping(self, mock_logger):
        """Threat Intel - Test private function to parse invalid types"""
        invalid_str = 'invalidType:ioc_test:foo'
        qualified, normalized_type, ioc_type = self.threat_intel._validate_type_mapping(invalid_str)
        assert_false(qualified)
        assert_equal(normalized_type, None)
        assert_equal(ioc_type, None)
        mock_logger.assert_called_with('Key %s in conf/types.json is incorrect', invalid_str)

    @patch('boto3.client')
    def test_process_ioc(self, mock_client):
        """Threat Intel - Test private method process_ioc"""
        mock_client.return_value = MockDynamoDBClient()
        threat_intel = StreamThreatIntel.load_from_config(self.config)

        ioc_collections = [
            StreamIoc(value='1.1.1.2', ioc_type='ip'),
            StreamIoc(value='2.2.2.2', ioc_type='ip'),
            StreamIoc(value='evil.com', ioc_type='domain')
        ]
        threat_intel._process_ioc(ioc_collections)
        assert_true(ioc_collections[0].is_ioc)
        assert_false(ioc_collections[1].is_ioc)
        assert_true(ioc_collections[2].is_ioc)

    @patch('boto3.client')
    @patch('logging.Logger.error')
    def test_process_ioc_with_clienterror(self, log_mock, mock_client):
        """Threat Intel - Test private method process_ioc with Error"""
        mock_client.return_value = MockDynamoDBClient(exception=True)
        threat_intel = StreamThreatIntel.load_from_config(self.config)

        ioc_collections = [
            StreamIoc(value='1.1.1.2', ioc_type='ip')
        ]
        threat_intel._process_ioc(ioc_collections)
        log_mock.assert_called_with('An error occured while quering dynamodb table. Error is: %s',
                                    {'Error': {'Code': 400, 'Message': 'raising test exception'}})

    @patch('boto3.client')
    def test_process_ioc_with_unprocessed_keys(self, mock_client):
        """Threat Intel - Test private method process_ioc when response has UnprocessedKeys"""
        mock_client.return_value = MockDynamoDBClient(unprocesed_keys=True)
        threat_intel = StreamThreatIntel.load_from_config(self.config)

        ioc_collections = [
            StreamIoc(value='1.1.1.2', ioc_type='ip'),
            StreamIoc(value='foo', ioc_type='domain'),
            StreamIoc(value='bar', ioc_type='domain')
        ]
        threat_intel._process_ioc(ioc_collections)
        assert_true(ioc_collections[0].is_ioc)
        assert_false(ioc_collections[1].is_ioc)
        assert_false(ioc_collections[2].is_ioc)

    def test_segment(self):
        """Threat Intel - Test _segment method to segment a list to sub-list"""
        # it should only return 1 sub-list when length of list less than MAX_QUERY_CNT (100)
        test_list = [item for item in range(55)]
        result = StreamThreatIntel._segment(test_list)
        assert_equal(len(result), 1)
        assert_equal(len(result[0]), 55)

        # it should return multiple sub-list when len of list more than MAX_QUERY_CNT (100)
        test_list = [item for item in range(345)]
        result = StreamThreatIntel._segment(test_list)
        assert_equal(len(result), 4)
        assert_equal(len(result[0]), 100)
        assert_equal(len(result[1]), 100)
        assert_equal(len(result[2]), 100)
        assert_equal(len(result[3]), 45)

    @patch('boto3.client')
    def test_query(self, mock_client):
        """Threat Intel - Test DynamoDB query method with batch_get_item"""
        mock_client.return_value = MockDynamoDBClient()
        threat_intel = StreamThreatIntel.load_from_config(self.config)

        test_values = ['1.1.1.2', '2.2.2.2', 'evil.com', 'abcdef0123456789']
        result, unprocessed_keys = threat_intel._query(test_values)
        assert_equal(len(result), 2)
        assert_false(unprocessed_keys)
        assert_equal(result[0], {'ioc_value': '1.1.1.2', 'sub_type': 'mal_ip'})
        assert_equal(result[1], {'ioc_value': 'evil.com', 'sub_type': 'c2_domain'})

    @patch('boto3.client')
    def test_query_with_empty_value(self, mock_client):
        """Threat Intel - Test query value includes empty value"""
        mock_client.return_value = MockDynamoDBClient()
        threat_intel = StreamThreatIntel.load_from_config(self.config)

        test_values = ['1.1.1.2', '', 'evil.com', 'abcdef0123456789']
        result, _ = threat_intel._query(test_values)
        assert_equal(len(result), 2)

    @raises(ParamValidationError)
    @patch('boto3.client')
    def test_query_with_duplicated_value(self, mock_client):
        """Threat Intel - Test query value includes dumplicated value"""
        mock_client.return_value = MockDynamoDBClient()
        threat_intel = StreamThreatIntel.load_from_config(self.config)

        test_values = ['1.1.1.2', 'EVIL.com', 'evil.com', 'abcdef0123456789']
        threat_intel._query(test_values)

    @raises(ClientError)
    @patch('boto3.client')
    def test_query_with_exception(self, mock_client):
        """Threat Intel - Test DynamoDB query method with exception"""
        mock_client.return_value = MockDynamoDBClient(exception=True)
        threat_intel = StreamThreatIntel.load_from_config(self.config)

        threat_intel._query(['1.1.1.2'])

    def test_deserialize(self):
        """Threat Intel - Test method to convert dynamodb types to python types"""
        test_dynamodb_data = [
            {
                'ioc_value': {'S': '1.1.1.2'},
                'sub_type': {'S': 'mal_ip'}
            },
            {
                'test_number': {'N': 10},
                'test_type': {'S': 'test_type'}
            }
        ]

        result = StreamThreatIntel._deserialize(test_dynamodb_data)
        expect_result = [
            {'ioc_value': '1.1.1.2', 'sub_type': 'mal_ip'},
            {'test_number': 10, 'test_type': 'test_type'}
        ]
        assert_equal(result, expect_result)

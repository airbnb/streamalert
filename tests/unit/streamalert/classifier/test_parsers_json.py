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
# pylint: disable=too-many-lines
import json
from unittest.mock import patch

from streamalert.classifier.parsers import JSONParser


class TestJSONParser:
    """Test class for JSONParser"""
    # pylint: disable=attribute-defined-outside-init,no-self-use,protected-access

    @classmethod
    def _json_regex_key_options(cls):
        return {
            'schema': {
                'nested_key_01': 'string',
                'nested_key_02': 'string'
            },
            'configuration': {
                'envelope_keys': {
                    'time': 'string',
                    'date': 'string',
                    'host': 'string'
                },
                'optional_envelope_keys': [
                    'host'
                ],
                'json_regex_key': 'message'
            }
        }

    def test_schema_fail(self):
        """JSONParser - Schema Match Failure"""
        options = {
            'schema': {
                'unit_key_01': 'integer',
                'unit_key_02': 'string'
            }
        }

        data = {'hey': 1}
        record_data = json.dumps(data)

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data) == False

        expected_result = [
            data
        ]
        assert parser.invalid_parses == expected_result

    def test_non_string_input(self):
        """JSONParser - Non String Input"""
        options = {
            'schema': {
                'name': 'string',
                'result': 'string'
            }
        }

        record_data = {'name': 'test', 'result': 'test'}

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [
            record_data
        ]
        assert parser.parsed_records == expected_result

    def test_invalid_json_path(self):
        """JSONParser - Invalid JSON Path"""
        options = {
            'schema': {
                'name': 'string',
                'result': 'string'
            },
            'configuration': {
                'json_path': 'Records[*]'
            }
        }

        record_data = {'name': 'test', 'result': 'test'}

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data) == False

        expected_result = [
            record_data
        ]
        assert parser.invalid_parses == expected_result

    def test_invalid_json(self):
        """JSONParser - Invalid Input"""
        options = {
            'schema': {
                'name': 'string',
                'result': 'string'
            }
        }

        record_data = 'not json data'

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data) == False

        expected_result = [
            record_data
        ]
        assert parser.invalid_parses == expected_result

    def test_envelope_keys_optional_values(self):
        """JSONParser - Default Values for Missing Envelope Keys"""
        options = self._json_regex_key_options()

        # missing 'host' envelope key
        record_data = json.dumps({
            'message': json.dumps({
                'nested_key_01': 'foo',
                'nested_key_02': 'bar'
            }),
            'date': '2017/10/01',
            'time': '14:00:00'
        })

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [
            {
                'nested_key_01': 'foo',
                'nested_key_02': 'bar',
                'streamalert:envelope_keys': {
                    'host': '',
                    'date': '2017/10/01',
                    'time': '14:00:00'
                }
            }
        ]
        assert parser.parsed_records == expected_result

    def test_regex_key_invalid_json(self):
        """JSONParser - Regex Key with Invalid JSON Object"""
        options = self._json_regex_key_options()

        # Invalid JSON and missing optional 'host' envelope key
        data = {
            'message': '{"nested_key_01": "test" "nested_key_02": "test"}',
            'date': '2017/10/01',
            'time': '14:00:00'
        }

        record_data = json.dumps(data)

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data) == False

        expected_result = [
            data
        ]
        assert parser.invalid_parses == expected_result

    def test_regex_key_json_list(self):
        """JSONParser - Regex Key with a List JSON Object"""
        options = self._json_regex_key_options()

        # JSON that does not match schema
        data = {
            'message': '["nested_key_01", "test"]',
            'date': '2017/10/01',
            'time': '14:00:00',
            'host': 'host-1'
        }

        record_data = json.dumps(data)

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data) == False

        expected_result = [
            data
        ]
        assert parser.invalid_parses == expected_result

    def test_regex_key_non_json(self):
        """JSONParser - Regex Key with Plaintext Input"""
        options = self._json_regex_key_options()

        # Invalid JSON for message key
        data = {
            'message': 'hey this is not JSON',
            'date': '2017/10/01',
            'time': '14:00:00',
            'host': 'my-host-1'
        }

        record_data = json.dumps(data)

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data) == False

        expected_result = [
            data
        ]
        assert parser.invalid_parses == expected_result

    @patch('logging.Logger.error')
    def test_optional_keys_missing_in_schema(self, log_mock):
        """JSONParser - Invalid Schema Definition"""
        options = {
            'schema': {
                'key1': [],
                'key2': 'string',
                'key3': 'integer',
                'key9': 'boolean',
                'key10': {},
                'key11': 'float'
            },
            'configuration': {
                'optional_top_level_keys': [
                    'key9',
                    'key10',
                    'key11',
                    'key12'
                ]
            }
        }

        record_data = json.dumps({
            'key1': [
                'test data',
                'moar test data'
            ],
            'key2': 'string data',
            'key3': 100,
            'key9': True
        })

        # get parsed data
        log_type = 'invaid_log'
        parser = JSONParser(options, log_type)
        assert parser.parse(record_data) == False
        log_mock.assert_called_with(
            'Schema definition is not valid (%s):\n%s',
            log_type,
            options['schema']
        )

    def test_single_nested_json(self):
        """JSONParser - Single nested JSON"""
        options = {
            'schema': {
                'middlekey1': 'string',
                'middlekey2': []
            },
            'configuration': {
                'json_path': 'topkey'
            }
        }

        expected_record = {
            'middlekey1': '1',
            'middlekey2': []
        }

        data = {
            'topkey': {
                'middlekey1': '1',
                'middlekey2': [],
            }
        }

        record_data = json.dumps(data)

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [
            expected_record
        ]
        assert parser.parsed_records == expected_result

    def test_multi_nested_json(self):
        """JSONParser - Multi-nested JSON"""
        options = {
            'schema': {
                'name': 'string',
                'result': 'string'
            },
            'configuration': {
                'json_path': 'profiles.controls[*]'
            }
        }

        expected_record = {
            'name': 'test-infra-1',
            'result': 'fail'
        }

        data = {
            'profiles': {
                'controls': [
                    expected_record
                ]
            }
        }

        record_data = json.dumps(data)

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [
            expected_record
        ]
        assert parser.parsed_records == expected_result

    def test_json_regex_key_with_envelope(self):
        """JSONParser - Regex key with envelope"""
        options = self._json_regex_key_options()

        # Valid record data
        record_data = json.dumps({
            'time': '14:01',
            'date': 'Jan 01, 2017',
            'host': 'host1.test.domain.tld',
            'message': '<10> auditd[1300] info: '
                       '{"nested_key_01": "foo",'
                       '"nested_key_02": "bar"}'
        })

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [
            {
                'nested_key_01': 'foo',
                'nested_key_02': 'bar',
                'streamalert:envelope_keys': {
                    'host': 'host1.test.domain.tld',
                    'date': 'Jan 01, 2017',
                    'time': '14:01'
                }
            }
        ]
        assert parser.parsed_records == expected_result

    def test_json_regex_key(self):
        """JSONParser - Regex key"""
        options = {
            'schema': {
                'nested_key_01': 'string',
                'nested_key_02': 'string'
            },
            'configuration': {
                'json_regex_key': 'message'
            }
        }

        record_data = json.dumps({
            'time': '14:01',
            'date': 'Jan 01, 2017',
            'host': 'host1.test.domain.tld',
            'message': '<10> auditd[1300] info: '
                       '{"nested_key_01": "nested_info",'
                       '"nested_key_02": "more_nested_info"}'
        })

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [
            {
                'nested_key_01': 'nested_info',
                'nested_key_02': 'more_nested_info'
            }
        ]

        assert parser.parsed_records == expected_result

    def test_embedded_json(self):
        """JSONParser - Embedded JSON"""
        options = {
            'schema': {
                'nested_key_01': 'string',
                'nested_key_02': 'string'
            },
            'configuration': {
                'embedded_json': True,
                'envelope_keys': {
                    'env_key_01': 'string',
                    'env_key_02': 'string'
                },
                'json_path': 'test_list[*].message'
            }
        }

        record_data = json.dumps({
            'env_key_01': 'data',
            'env_key_02': 'time',
            'test_list': [
                {
                    'id': 'foo',
                    'message': json.dumps({
                        'nested_key_01': 'bar',
                        'nested_key_02': 'baz'
                    })
                }
            ]
        })

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [
            {
                'nested_key_01': 'bar',
                'nested_key_02': 'baz',
                'streamalert:envelope_keys': {
                    'env_key_01': 'data',
                    'env_key_02': 'time'
                }
            }
        ]

        assert parser.parsed_records == expected_result

    def test_embedded_json_invalid(self):
        """JSONParser - Embedded JSON, Invalid"""
        options = {
            'schema': {
                'nested_key_01': 'string',
                'nested_key_02': 'string'
            },
            'configuration': {
                'embedded_json': True,
                'envelope_keys': {
                    'env_key_01': 'string',
                    'env_key_02': 'string'
                },
                'json_path': 'test_list[*].message'
            }
        }

        invalid_data = '{\"invalid_json\"}'

        record_data = json.dumps({
            'env_key_01': 'data',
            'env_key_02': 'time',
            'test_list': [
                {
                    'id': 'foo',
                    'message': invalid_data
                }
            ]
        })

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data) == False

        expected_result = [
            invalid_data
        ]

        assert parser.invalid_parses == expected_result

    def test_basic_json(self):
        """JSONParser - Non-nested JSON objects"""
        options = {
            'schema': {
                'name': 'string',
                'age': 'integer'
            }
        }

        data = {
            'name': 'john',
            'age': 30
        }

        record_data = json.dumps(data)

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [
            data
        ]

        assert parser.parsed_records == expected_result

    def test_optional_keys_json(self):
        """JSONParser - Optional top level keys"""
        options = {
            'schema': {
                'columns': {},
                'host': 'string',
                'host-id': 'integer',
                'ids': [],
                'name': 'string',
                'results': {},
                'valid': 'boolean'
            },
            'configuration': {
                'optional_top_level_keys': [
                    'host-id',
                    'ids',
                    'results',
                    'valid'
                ]
            }
        }

        record_data = json.dumps({
            'columns': {
                'test-column': 1
            },
            'host': 'unit-test-host-1',
            'name': 'unit-test',
            'valid': 'true'
        })

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [
            {
                'columns': {
                    'test-column': 1
                },
                'host': 'unit-test-host-1',
                'host-id': 0,
                'ids': [],
                'name': 'unit-test',
                'results': {},
                'valid': True
            }
        ]

        assert parser.parsed_records == expected_result

    def test_nested_records_with_missing_keys(self):
        """JSONParser - Nested records with missing keys"""
        options = {
            'schema': {
                'computer_name': 'string',
                'group': 'integer'
            },
            'configuration': {
                'json_path': 'Records[*]'
            }
        }

        record_data = json.dumps({
            'Records': [
                {
                    'computer_name': 'foo',
                    'group': 3
                },
                {
                    'computer_name': 'foo-bar',
                    'group': 3
                },
                {
                    # Missing group key
                    'computer_name': 'foo-bar-baz'
                }
            ]
        })

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_valid_result = [
            {
                'computer_name': 'foo',
                'group': 3
            },
            {
                'computer_name': 'foo-bar',
                'group': 3
            }
        ]

        expected_invalid_result = [
            {
                'computer_name': 'foo-bar-baz'
            }
        ]

        assert parser.parsed_records == expected_valid_result
        assert parser.invalid_parses == expected_invalid_result

    def test_optional_keys_with_json_path(self):
        """JSONParser - Optional top level keys and json path"""
        options = {
            'schema': {
                'md5': 'string',
                'opt_key': 'string',
                'another_opt_key': 'string'
            },
            'configuration': {
                'json_path': 'docs[*]',
                'optional_top_level_keys': [
                    'opt_key',
                    'another_opt_key'
                ]
            }
        }

        record_data = json.dumps({
            'server': 'test_server',
            'username': 'test_user',
            'docs': [
                {
                    'md5': '58B8702C20DE211D1FCB248D2FDD71D1',
                    'opt_key': 'exists'
                },
                {
                    'md5': '1D1FCB248D2FDD71D158B8702C20DE21',
                    'opt_key': 'this_value_is_optional',
                    'another_opt_key': 'this_value_is_also_optional'
                },
                {
                    'md5': '1D1FCB248D2FDD71D158B8702C20DE21'
                }
            ]
        })

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [
            {
                'md5': '58B8702C20DE211D1FCB248D2FDD71D1',
                'opt_key': 'exists',
                'another_opt_key': ''
            },
            {
                'md5': '1D1FCB248D2FDD71D158B8702C20DE21',
                'opt_key': 'this_value_is_optional',
                'another_opt_key': 'this_value_is_also_optional'
            },
            {
                'md5': '1D1FCB248D2FDD71D158B8702C20DE21',
                'opt_key': '',
                'another_opt_key': ''
            }
        ]

        assert parser.parsed_records == expected_result

    def test_cloudtrail(self):
        """JSONParser - Cloudtrail JSON"""
        options = {
            'schema': {
                'eventVersion': 'string',
                'eventID': 'string',
                'eventTime': 'string',
                'requestParameters': {},
                'eventType': 'string',
                'responseElements': 'string',
                'awsRegion': 'string',
                'eventName': 'string',
                'userIdentity': {},
                'eventSource': 'string',
                'requestID': 'string',
                'userAgent': 'string',
                'sourceIPAddress': 'string',
                'recipientAccountId': 'string'
            },
            'configuration': {
                'json_path': 'Records[*]'
            }
        }

        data = {
            'Records': [
                {
                    'eventVersion': '1.0.0',
                    'eventID': '0000000',
                    'eventTime': '2016-12-31T12:00:00Z',
                    'requestParameters': {
                        'streamName': 'streamalert'
                    },
                    'eventType': 'AwsApiCall',
                    'responseElements': None,
                    'awsRegion': 'us-west-1',
                    'eventName': 'DescribeStream',
                    'userIdentity': {
                        'userName': 'streamalert_user',
                        'principalId': 'AAAAAAAAAAAAAAAA',
                        'accessKeyId': 'FFFFFFFFFFFFFFFFFF',
                        'type': 'IAMUser',
                        'arn': 'arn:aws:iam::111111111111:user/streamalert_user',
                        'accountId': '111111111111'
                    },
                    'eventSource': 'kinesis.amazonaws.com',
                    'requestID': 'dddddddddd',
                    'userAgent': 'aws-sdk',
                    'sourceIPAddress': '127.0.0.1',
                    'recipientAccountId': '1111111111111'
                },
                {
                    'eventVersion': '2.0.0',
                    'eventID': '1111111',
                    'eventTime': '2017-01-31T12:00:00Z',
                    'requestParameters': {
                        'streamName': 'streamalert_prod'
                    },
                    'eventType': 'AwsApiCall',
                    'responseElements': None,
                    'awsRegion': 'us-east-1',
                    'eventName': 'DescribeStream',
                    'userIdentity': {
                        'userName': 'streamalert_prod_user',
                        'principalId': 'BBBBBBBBBBBBBBBB',
                        'accessKeyId': 'GGGGGGGGGGGGGGGG',
                        'type': 'IAMUser',
                        'arn': 'arn:aws:iam::222222222222:user/streamalert_prod_user',
                        'accountId': '222222222222'
                    },
                    'eventSource': 'kinesis.amazonaws.com',
                    'requestID': 'dddddddddd',
                    'userAgent': 'aws-sdk',
                    'sourceIPAddress': '127.0.0.2',
                    'recipientAccountId': '222222222222'
                }
            ]
        }

        record_data = json.dumps(data)

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = data['Records']

        assert parser.parsed_records == expected_result

    def test_cloudwatch(self):
        """JSONParser - CloudWatch JSON with envelope keys"""
        options = {
            'schema': {
                'account': 'integer',
                'action': 'string',
                'bytes': 'integer',
                'destination': 'string',
                'destport': 'integer',
                'eni': 'string',
                'flowlogstatus': 'string',
                'packets': 'integer',
                'protocol': 'integer',
                'source': 'string',
                'srcport': 'integer',
                'version': 'integer',
                'windowend': 'integer',
                'windowstart': 'integer'
            },
            'configuration': {
                'json_path': 'logEvents[*].extractedFields',
                'envelope_keys': {
                    'logGroup': 'string',
                    'logStream': 'string',
                    'owner': 'integer'
                }
            }
        }

        record_data = json.dumps({
            'logEvents': [
                {
                    'extractedFields': {
                        'account': '123456789012',
                        'action': 'REJECT',
                        'bytes': '240',
                        'destination': '172.31.12.209',
                        'destport': '80',
                        'eni': 'eni-77ccbe24',
                        'flowlogstatus': 'OK',
                        'packets': '4',
                        'protocol': '6',
                        'source': '172.31.1.54',
                        'srcport': '27974',
                        'version': '2',
                        'windowend': '1488216389',
                        'windowstart': '1488216331'
                    },
                    'id': '33188333197923110564639124232124531540364522455662723073',
                    'message': ('2 123456789012 eni-77ccbe24 172.31.1.54 172.31.12.209 '
                                '27974 80 6 4 240 1488216331 1488216389 REJECT OK'),
                    'timestamp': 1488216331000
                },
                {
                    'extractedFields': {
                        'account': '123456789012',
                        'action': 'REJECT',
                        'bytes': '240',
                        'destination': '172.31.12.209',
                        'destport': '80',
                        'eni': 'eni-77ccbe24',
                        'flowlogstatus': 'OK',
                        'packets': '4',
                        'protocol': '6',
                        'source': '172.31.39.106',
                        'srcport': '22598',
                        'version': '2',
                        'windowend': '1488216389',
                        'windowstart': '1488216331'
                    },
                    'id': '33188333197923110564639124232124531540364522455662723074',
                    'message': ('2 123456789012 eni-77ccbe24 172.31.39.106 172.31.12.209 '
                                '22598 80 6 4 240 1488216331 1488216389 REJECT OK'),
                    'timestamp': 1488216331000
                }
            ],
            'logGroup': 'airdev_prod_streamalert_flow_logs',
            'logStream': 'eni-77ccbe24-all',
            'messageType': 'DATA_MESSAGE',
            'owner': '123456789012',
            'subscriptionFilters': [
                'airdev_prod_streamalert_flow_logs_to_lambda'
            ]
        })

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [
            {
                'account': 123456789012,
                'action': 'REJECT',
                'bytes': 240,
                'destination': '172.31.12.209',
                'destport': 80,
                'eni': 'eni-77ccbe24',
                'flowlogstatus': 'OK',
                'packets': 4,
                'protocol': 6,
                'source': '172.31.1.54',
                'srcport': 27974,
                'version': 2,
                'windowend': 1488216389,
                'windowstart': 1488216331,
                'streamalert:envelope_keys': {
                    'logGroup': 'airdev_prod_streamalert_flow_logs',
                    'logStream': 'eni-77ccbe24-all',
                    'owner': 123456789012
                }
            },
            {
                'account': 123456789012,
                'action': 'REJECT',
                'bytes': 240,
                'destination': '172.31.12.209',
                'destport': 80,
                'eni': 'eni-77ccbe24',
                'flowlogstatus': 'OK',
                'packets': 4,
                'protocol': 6,
                'source': '172.31.39.106',
                'srcport': 22598,
                'version': 2,
                'windowend': 1488216389,
                'windowstart': 1488216331,
                'streamalert:envelope_keys': {
                    'logGroup': 'airdev_prod_streamalert_flow_logs',
                    'logStream': 'eni-77ccbe24-all',
                    'owner': 123456789012
                }
            }
        ]
        assert parser.parsed_records == expected_result

    def test_inspec(self):
        """JSONParser - Inspec JSON"""
        options = {
            'schema': {
                'title': 'string',
                'desc': 'string',
                'impact': 'float',
                'refs': [],
                'tags': {},
                'code': 'string',
                'id': 'string',
                'source_location': {},
                'results': []
            },
            'configuration': {
                'json_path': 'profiles[].controls[]'
            }
        }

        data = {
            'other_checks': [],
            'profiles': [
                {
                    'attributes': [],
                    'controls': [
                        {
                            'code': 'code snippet 01',
                            'desc': None,
                            'id': '(generated from osquery.rb:1 b6ef5242a32098111f11cb7d21a05bb8)',
                            'impact': 0.5,
                            'refs': [],
                            'results': [
                                {
                                    'code_desc': 'Processes states should eq [\'SNs\']',
                                    'run_time': 0.000992,
                                    'start_time': '2017-02-28 09:24:47 -0800',
                                    'status': 'passed'
                                }
                            ],
                            'source_location': {
                                'line': 87,
                                'ref': '/opt/inspec/.../control_eval_context.rb'
                            },
                            'tags': {},
                            'title': None
                        },
                        {
                            'code': 'code snippet 02',
                            'desc': None,
                            'id': '(generated from osquery.rb:6 124c5f23cd897a018673b1ea512a9473)',
                            'impact': 0.5,
                            'refs': [],
                            'results': [
                                {
                                    'code_desc': 'File osquery.conf mode should cmp == \'0400\'',
                                    'message': 'foo message',
                                    'run_time': 0.011729,
                                    'start_time': '2017-02-28 09:24:47 -0800',
                                    'status': 'failed'
                                }
                            ],
                            'source_location': {
                                'line': 87,
                                'ref': '/opt/inspec/.../control_eval_context.rb'
                            },
                            'tags': {},
                            'title': None
                        }
                    ],
                    'groups': [
                        {
                            'controls': [
                                '(generated from osquery.rb:1 b6ef5242a32098111f11cb7d21a05bb8)'
                            ],
                            'id': 'osquery.rb',
                            'title': None
                        }
                    ],
                    'supports': []
                }
            ],
            'statistics': {
                'duration': 0.040234
            },
            'version': '1.4.1'
        }

        record_data = json.dumps(data)

        # get parsed data
        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [
            control for prof in data['profiles'] for control in prof['controls']
        ]

        assert parser.parsed_records == expected_result

    def test_parse_record_copy(self):
        """JSONParser - Parse, Ensure Copy"""
        options = {
            'schema': {
                'key': 'string'
            }
        }
        record_data = {
            'key': 'value'
        }

        parser = JSONParser(options)
        assert parser.parse(record_data)
        assert id(parser.parsed_records[0]) != id(record_data)

    @patch('logging.Logger.debug')
    def test_extract_via_json_path_bad_json(self, log_mock):
        """JSONParser - Extract via JSON Path, Bad JSON"""
        options = {
            'schema': {
                'key': 'string'
            },
            'configuration': {
                'embedded_json': True,
                'json_path': 'key[].value'
            }
        }
        record_data = {
            'key': [
                {
                    'value': 'not json'
                }
            ]
        }

        parser = JSONParser(options)
        result = parser._extract_via_json_path(record_data)
        assert result == [('not json', False)]
        log_mock.assert_any_call('Embedded json is invalid: %s',
                                 'Expecting value: line 1 column 1 (char 0)')

    @patch('logging.Logger.debug')
    def test_extract_via_json_path_not_dict(self, log_mock):
        """JSONParser - Extract via JSON Path, Not Dictionary"""
        options = {
            'schema': {
                'key': 'string'
            },
            'configuration': {
                'embedded_json': True,
                'json_path': 'key[].value'
            }
        }
        record_data = {
            'key': [
                {
                    'value': '["list of data"]'
                }
            ]
        }

        parser = JSONParser(options)
        result = parser._extract_via_json_path(record_data)
        assert result == [(['list of data'], False)]
        log_mock.assert_any_call('Embedded json is invalid: %s', 'record data is not a dictionary')

    def test_extract_via_json_regex_key_no_key(self):
        """JSONParser - Extract via JSON Regex Key, Key Does Not Exist"""
        options = {
            'schema': {
                'key': 'string'
            },
            'configuration': {
                'json_regex_key': 'key_01'
            }
        }
        record_data = {
            'key': 'value'
        }

        parser = JSONParser(options)
        result = parser._extract_via_json_regex_key(record_data)
        assert result == False

    def test_parse_record_not_dict_mismatch(self):
        """JSONParser - Parse record not in dict type and doesn't match schema"""
        options = {
            'schema': {
                'key': 'string'
            },
            'parser': 'json'
        }
        record_data = "[{\"key\": \"value\"}]"

        parser = JSONParser(options)
        assert parser.parse(record_data) == False

    def test_parse_record_not_dict_matched(self):
        """JSONParser - Parse record not in dict type but match the schema"""
        options = {
            'schema': {
                'key': 'string'
            },
            'parser': 'json',
            'configuration': {
                'json_path': "[*]"
            }
        }
        record_data = "[{\"key\": \"value\"}]"

        parser = JSONParser(options)
        assert parser.parse(record_data)

        expected_result = [{'key': 'value'}]
        assert parser.parsed_records == expected_result

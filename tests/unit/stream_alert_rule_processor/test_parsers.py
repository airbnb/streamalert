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
import json

from mock import patch
from nose.tools import (
    assert_equal,
    assert_false,
    assert_is_instance,
    assert_items_equal,
    assert_not_equal,
    assert_true
)

from stream_alert.rule_processor.config import load_config
from stream_alert.rule_processor.parsers import get_parser


class TestParser(object):
    """Base class for parser tests"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        # load config
        cls.config = load_config('tests/unit/conf')
        # load the parser class
        cls.parser_class = get_parser(cls._parser_type())

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.config = None
        cls.parser_class = None

    @classmethod
    def _parser_type(cls):
        pass

    def parser_helper(self, data, schema, options=None):
        """Helper to return the parser result"""
        parser = self.parser_class(options)
        parsed_result = parser.parse(schema, data)
        return parsed_result


class TestKVParser(TestParser):
    """Test class for KVParser"""
    @classmethod
    def _parser_type(cls):
        return 'kv'

    def test_kv_parsing(self):
        """KV Parser - Basic key value pairs"""
        # setup
        schema = {
            'name': 'string',
            'result': 'string'
        }
        options = {
            'separator': ':',
            'delimiter': ',',
        }
        data = 'name:joe bob,result:success'

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema, options=options)

        assert_equal(len(parsed_data), 1)
        assert_equal(parsed_data[0]['name'], 'joe bob')


class TestJSONParser(TestParser):
    """Test class for JSONParser"""
    @classmethod
    def _parser_type(cls):
        return 'json'

    def test_schema_fail(self):
        """JSON Parser - Schema Match Failure"""
        # setup
        schema = self.config['logs']['unit_test_simple_log']['schema']
        data = json.dumps({'hey': 1})

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema)

        assert_false(parsed_data)

    def test_non_string_input(self):
        """JSON Parser - Non String Input"""
        # setup
        schema = {'name': 'string', 'result': 'string'}
        data = {'name': 'test', 'result': 'test'}

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema)

        assert_equal(len(parsed_data), 1)

    def test_invalid_json_path(self):
        """JSON Parser - Invalid JSON Path"""
        # setup
        schema = {'name': 'string', 'result': 'string'}
        data = {'name': 'test', 'result': 'test'}
        options = {'json_path': 'Records[*]'}

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema, options=options)

        assert_false(parsed_data)

    @patch('stream_alert.rule_processor.parsers.LOGGER')
    def test_invalid_json(self, mock_logging):
        """JSON Parser - Invalid Input"""
        # setup
        schema = {'name': 'string', 'result': 'string'}
        data = 'not json data'

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema)

        assert_true(mock_logging.debug.called)
        assert_false(parsed_data)

    def test_envelope_keys_optional_values(self):
        """JSON Parser - Default Values for Missing Envelope Keys"""
        options = self.config['logs']['json:regex_key_with_envelope']['configuration']
        schema = self.config['logs']['json:regex_key_with_envelope']['schema']
        # missing 'host' envelope key
        data = json.dumps({
            'message': '{"nested_key_1": "test"'
                       ', "nested_key_2": "test"'
                       ', "nested_key_3": "test"}',
            'date': '2017/10/01',
            'time': '14:00:00'
        })

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema, options=options)

        assert_equal(len(parsed_data), 1)
        assert_true(parsed_data[0]['streamalert:envelope_keys']['host'] == '')

    @patch('stream_alert.rule_processor.parsers.LOGGER')
    def test_regex_key_invalid_json(self, mock_logging):
        """JSON Parser - Regex Key with Invalid JSON Object"""
        options = self.config['logs']['json:regex_key_with_envelope']['configuration']
        schema = self.config['logs']['json:regex_key_with_envelope']['schema']
        # Invalid JSON and missing 'host' envelope key
        data = json.dumps({
            'message': '{"nested_key_1": "test"'
                       ' "nested_key_2": "test"'
                       ' "nested_key_3": "test"}',
            'date': '2017/10/01',
            'time': '14:00:00'
        })

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema, options=options)

        assert_true(mock_logging.debug.called)
        assert_false(parsed_data)

    def test_regex_key_json_list(self):
        """JSON Parser - Regex Key with a List JSON Object"""
        options = self.config['logs']['json:regex_key_with_envelope']['configuration']
        schema = self.config['logs']['json:regex_key_with_envelope']['schema']
        # Invalid JSON and missing 'host' envelope key
        data = json.dumps({
            'message': '["nested_key_1", "test"]',
            'date': '2017/10/01',
            'time': '14:00:00',
            'host': 'host-1'
        })

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema, options=options)

        assert_false(parsed_data)

    def test_regex_key_non_json(self):
        """JSON Parser - Regex Key with Plaintext Input"""
        options = self.config['logs']['json:regex_key_with_envelope']['configuration']
        schema = self.config['logs']['json:regex_key_with_envelope']['schema']
        data = json.dumps({
            # invalid JSON below
            'message': 'hey this is not JSON',
            'date': '2017/10/01',
            'time': '14:00:00',
            'host': 'my-host-1'
        })

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema, options=options)
        assert_false(parsed_data)

    @patch('stream_alert.rule_processor.parsers.LOGGER')
    def test_optional_keys_missing_in_schema(self, mock_logging):
        """JSON Parser - Optional Top Level Keys Not in Schema"""
        options = {
            'optional_top_level_keys': [
                'key9',
                'key10',
                'key11',
                'key12'
            ]
        }
        schema = self.config['logs']['test_log_type_json']['schema']
        data = json.dumps({
            'key1': [
                'test data',
                'moar test data'
            ],
            'key2': 'string data',
            'key3': 100,
            'key9': True
        })

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema, options=options)

        assert_true(mock_logging.error.called)
        assert_true(parsed_data)

    def test_multi_nested_json(self):
        """JSON Parser - Multi-nested JSON"""
        # setup
        schema = {
            'name': 'string',
            'result': 'string'
        }
        options = {'json_path': 'profiles.controls[*]'}

        data = json.dumps({
            'profiles': {
                'controls': [{
                    'name': 'test-infra-1',
                    'result': 'fail'
                }]
            }
        })

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema, options=options)

        assert_equal(len(parsed_data), 1)
        assert_equal(parsed_data[0]['result'], 'fail')

    def test_inspec(self):
        """JSON Parser - Inspec JSON"""
        schema = self.config['logs']['test_inspec']['schema']
        options = self.config['logs']['test_inspec']['configuration']

        # load fixture file
        with open('tests/unit/fixtures/inspec.json', 'r') as fixture_file:
            data = fixture_file.readline().strip()

        # setup json parser
        parsed_result = self.parser_helper(data=data,
                                           schema=schema,
                                           options=options)

        assert_equal(len(parsed_result), 2)
        inspec_keys = ['impact', 'code', 'tags', 'source_location', 'refs',
                       'title', 'results', 'id', 'desc']
        assert_items_equal(parsed_result[0].keys(), inspec_keys)

    def test_cloudtrail(self):
        """JSON Parser - Cloudtrail JSON"""
        schema = self.config['logs']['test_cloudtrail']['schema']
        options = self.config['logs']['test_cloudtrail']['configuration']

        # load fixture file
        with open('tests/unit/fixtures/cloudtrail.json', 'r') as fixture_file:
            data = fixture_file.readline().strip()

        # setup json parser
        parsed_result = self.parser_helper(data=data,
                                           schema=schema,
                                           options=options)

        assert_equal(len(parsed_result), 2)
        assert_equal(len(parsed_result[0].keys()), 14)
        assert_equal(len(parsed_result[1].keys()), 14)

        assert_equal(parsed_result[0]['eventVersion'], '1.0.0')
        assert_equal(parsed_result[0]['requestParameters']['streamName'],
                     'stream_alert')
        assert_equal(parsed_result[0]['userIdentity']['userName'],
                     'stream_alert_user')

        assert_equal(parsed_result[1]['awsRegion'], 'us-east-1')
        assert_equal(parsed_result[1]['requestParameters']['streamName'],
                     'stream_alert_prod')
        assert_equal(parsed_result[1]['userIdentity']['userName'],
                     'stream_alert_prod_user')

    def test_cloudwatch(self):
        """JSON Parser - CloudWatch JSON with envelope keys"""
        schema = self.config['logs']['test_cloudwatch']['schema']
        options = self.config['logs']['test_cloudwatch']['configuration']

        with open('tests/unit/fixtures/cloudwatch.json', 'r') as fixture_file:
            data = fixture_file.readline().strip()

        parsed_result = self.parser_helper(data=data,
                                           schema=schema,
                                           options=options)

        assert_not_equal(parsed_result, False)
        assert_equal(80, len(parsed_result))

        expected_keys = ['protocol', 'source', 'destination', 'srcport',
                         'destport', 'eni', 'action', 'packets', 'bytes',
                         'windowstart', 'windowend', 'version', 'account',
                         'flowlogstatus', 'streamalert:envelope_keys']
        expected_envelope_keys = ['logGroup', 'logStream', 'owner']

        for result in parsed_result:
            assert_items_equal(result.keys(), expected_keys)
            assert_items_equal(result['streamalert:envelope_keys'].keys(),
                               expected_envelope_keys)

    def test_json_regex_key_with_envelope(self):
        """JSON Parser - Regex key with envelope"""
        schema = self.config['logs']['json:regex_key_with_envelope']['schema']
        options = self.config['logs']['json:regex_key_with_envelope']['configuration']

        data = json.dumps({
            'time': '14:01',
            'date': 'Jan 01, 2017',
            'host': 'host1.test.domain.tld',
            'message': '<10> auditd[1300] info: '
                       '{"nested_key_1": "nested_info",'
                       '"nested_key_2": "more_nested_info",'
                       '"nested_key_3": "even_more"}'
        })
        parsed_result = self.parser_helper(data=data,
                                           schema=schema,
                                           options=options)

        assert_items_equal(parsed_result[0]['streamalert:envelope_keys'].keys(),
                           ['date', 'time', 'host'])
        assert_items_equal(parsed_result[0].keys(),
                           ['nested_key_1',
                            'nested_key_2',
                            'nested_key_3',
                            'streamalert:envelope_keys'])

    def test_json_regex_key(self):
        """JSON Parser - Regex key"""
        schema = self.config['logs']['json:regex_key']['schema']
        options = self.config['logs']['json:regex_key']['configuration']

        data = json.dumps({
            'time': '14:01',
            'date': 'Jan 01, 2017',
            'host': 'host1.test.domain.tld',
            'message': '<10> auditd[1300] info: '
                       '{"nested_key_1": "nested_info",'
                       '"nested_key_2": "more_nested_info",'
                       '"nested_key_3": "even_more"}'
        })
        parsed_result = self.parser_helper(data=data,
                                           schema=schema,
                                           options=options)

        assert_items_equal(parsed_result[0].keys(),
                           ['nested_key_1',
                            'nested_key_2',
                            'nested_key_3'])

    def test_basic_json(self):
        """JSON Parser - Non-nested JSON objects"""
        # setup
        schema = {
            'name': 'string',
            'age': 'integer',
            'city': 'string',
            'state': 'string'
        }
        options = None
        data = '{"name": "john", "age": 30, "city": "San Francisco", "state": "CA"}'

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema, options=options)

        # tests
        assert_items_equal(parsed_data[0].keys(), ['name', 'age', 'city', 'state'])
        assert_equal(parsed_data[0]['name'], 'john')
        assert_is_instance(parsed_data[0]['age'], int)

    def test_optional_keys_json(self):
        """JSON Parser - Optional top level keys"""
        schema = {
            'columns': {},
            'host': 'string',
            'host-id': 'integer',
            'ids': [],
            'name': 'string',
            'results': {},
            'valid': 'boolean'
        }
        options = {
            'optional_top_level_keys': [
                'host-id',
                'ids',
                'results',
                'valid'
            ]
        }
        data = json.dumps({
            'name': 'unit-test',
            'host': 'unit-test-host-1',
            'columns': {
                'test-column': 1
            },
            'valid': 'true'
        })
        parsed_result = self.parser_helper(data=data,
                                           schema=schema,
                                           options=options)

        # tests
        assert_equal(parsed_result[0]['host'], 'unit-test-host-1')
        assert_equal(parsed_result[0]['valid'], 'true')

        # test optional fields
        assert_equal(parsed_result[0]['host-id'], 0)
        assert_is_instance(parsed_result[0]['ids'], list)
        assert_is_instance(parsed_result[0]['results'], dict)

    def test_nested_records_with_missing_keys(self):
        """JSON Parser - Nested records with missing keys"""
        schema = {
            'computer_name': 'string',
            'date': 'string',
            'time': 'string',
            'group': 'integer',
            'production': 'boolean'
        }
        options = {
            'json_path': 'Records[*]'
        }
        data = json.dumps({
            'Records': [
                {
                    'computer_name': 'wethebest-01.prod.streamalert.io',
                    'date': 'Jan 01, 1980',
                    'time': '1230',
                    'group': 3,
                    'production': True
                },
                {
                    'computer_name': 'wethebest-02.prod.streamalert.io',
                    'date': 'Jan 02, 1980',
                    'time': '1330',
                    'group': 3,
                    'production': False
                },
                {
                    'computer_name': 'wethebest-03.prod.streamalert.io',
                    'date': 'Jan 03, 1980',
                    'time': '1430',
                    # Missing group key
                    'production': True
                }
            ]
        })

        parsed_result = self.parser_helper(data=data,
                                           schema=schema,
                                           options=options)

        assert_equal(len(parsed_result), 2)
        # Verify the third record is not considered valid
        assert_false(any([record['computer_name'] ==
                          'wethebest-03.prod.streamalert.io' for record in parsed_result]))

    def test_optional_keys_with_json_path(self):
        """JSON Parser - Optional top level keys and json path"""
        schema = {
            'internal_name': 'string',
            'is_64bit': 'boolean',
            'is_executable': 'boolean',
            'last_seen': 'string',
            'md5': 'string',
            'opt_key': 'string',
            'another_opt_key': 'string'
        }
        options = {
            'json_path': 'docs[*]',
            'optional_top_level_keys': [
                'opt_key',
                'another_opt_key'
            ]
        }
        data = json.dumps({
            'server': 'test_server',
            'username': 'test_user',
            'docs': [
                {
                    'internal_name': 'testname01',
                    'is_64bit': False,
                    'is_executable': True,
                    'last_seen': '20170707',
                    'md5': '58B8702C20DE211D1FCB248D2FDD71D1',
                    'opt_key': 'exists'
                },
                {
                    'internal_name': 'testname02',
                    'is_64bit': True,
                    'is_executable': True,
                    'last_seen': '20170706',
                    'md5': '1D1FCB248D2FDD71D158B8702C20DE21',
                    'opt_key': 'this_value_is_optional',
                    'another_opt_key': 'this_value_is_also_optional'
                },
                {
                    'internal_name': 'testname02',
                    'is_64bit': True,
                    'is_executable': True,
                    'last_seen': '20170701',
                    'md5': '1D1FCB248D2FDD71D158B8702C20DE21'
                }
            ]
        })

        parsed_result = self.parser_helper(data=data,
                                           schema=schema,
                                           options=options)

        # tests
        assert_equal(len(parsed_result), 3)
        assert_equal(parsed_result[0]['internal_name'], 'testname01')
        assert_equal(parsed_result[0]['md5'], '58B8702C20DE211D1FCB248D2FDD71D1')

        # test optional fields
        assert_equal(parsed_result[0]['opt_key'], 'exists')
        assert_equal(parsed_result[1]['another_opt_key'], 'this_value_is_also_optional')
        assert_equal(parsed_result[2]['opt_key'], '')

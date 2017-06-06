'''
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
'''
import json

from nose.tools import assert_equal

from stream_alert.rule_processor.config import load_config
from stream_alert.rule_processor.parsers import get_parser


class TestJSONParser(object):
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        # load config
        cls.config = load_config('test/unit/conf')
        # load JSON parser class
        cls.parser_class = get_parser('json')

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.config = None
        cls.parser_class = None

    def parser_helper(self, **kwargs):
        """Helper to return the parser result"""
        data = kwargs['data']
        schema = kwargs['schema']
        options = kwargs['options']

        json_parser = self.parser_class(options)
        parsed_result = json_parser.parse(schema, data)
        return parsed_result

    def test_multi_nested_json(self):
        """Parse Multi-layered JSON"""
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
        """Parse Inspec JSON"""
        schema = self.config['logs']['test_inspec']['schema']
        options = self.config['logs']['test_inspec']['configuration']

        # load fixture file
        with open('test/unit/fixtures/inspec.json', 'r') as fixture_file:
            data = fixture_file.readlines()

        data_record = data[0].strip()
        # setup json parser
        parsed_result = self.parser_helper(data=data_record,
                                           schema=schema,
                                           options=options)

        assert_equal(len(parsed_result), 2)
        inspec_keys = (u'impact', u'code', u'tags', u'source_location', u'refs',
                       u'title', u'results', u'id', u'desc')
        assert_equal(sorted((inspec_keys)), sorted(parsed_result[0].keys()))

    def test_cloudtrail(self):
        """Parse Cloudtrail JSON"""
        schema = self.config['logs']['test_cloudtrail']['schema']
        options = self.config['logs']['test_cloudtrail']['configuration']

        # load fixture file
        with open('test/unit/fixtures/cloudtrail.json', 'r') as fixture_file:
            data = fixture_file.readlines()

        data_record = data[0].strip()
        # setup json parser
        parsed_result = self.parser_helper(data=data_record,
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

    def test_basic_json(self):
        """Parse Non-nested JSON objects"""
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
        assert_equal(set(parsed_data[0].keys()), {'name', 'age', 'city', 'state'})
        assert_equal(parsed_data[0]['name'], 'john')
        assert_equal(type(parsed_data[0]['age']), int)

    def test_optional_keys_json(self):
        """Parse JSON with optional top level keys"""
        schema = {
            'name': 'string',
            'host': 'string',
            'columns': {}
        }
        options = {
            'optional_top_level_keys': {
                'ids': [],
                'results': {},
                'host-id': 'integer',
                'valid': 'boolean'
            }
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
        assert_equal(parsed_result[0]['ids'], [])
        assert_equal(parsed_result[0]['results'], {})

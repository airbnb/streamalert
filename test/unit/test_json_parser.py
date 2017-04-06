from stream_alert.rule_processor.config import load_config
from stream_alert.rule_processor.parsers import get_parser

import json

from nose.tools import (
    assert_equal,    
)


class TestJSONParser(object):
    @classmethod
    def setup_class(cls):
        """setup_class() before any methods in this class"""
        pass

    @classmethod
    def teardown_class(cls):
        """teardown_class() after any methods in this class"""
        pass

    def setup(self):
        """Setup before each method"""
        # load config
        self.config = load_config('test/unit/conf')
        # load JSON parser class
        self.parser_class = get_parser('json')

    def teardown(self):
        """Teardown after each method"""
        pass

    def parser_helper(self, **kwargs):
        data = kwargs['data']
        schema = kwargs['schema']
        options = kwargs['options']

        json_parser = self.parser_class(data, schema, options)
        parsed_result = json_parser.parse()
        return parsed_result

    def test_multi_nested_json(self):
        """Parse Multi-layered JSON"""
        # setup
        schema = {
            'name': 'string',
            'result': 'string'
        }
        options = {
            'configuration': {
                'json_path': 'profiles.controls[*]'
            }
        }
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
        options = {
            'configuration': self.config['logs']['test_inspec']['configuration']
        }
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
        options = {
            'configuration': self.config['logs']['test_cloudtrail']['configuration']
        }
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
            'configuration': {
                'optional_top_level_keys': {
                    'ids': [],
                    'results': {},
                    'host-id': 'integer',
                    'valid': 'boolean'
                }
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

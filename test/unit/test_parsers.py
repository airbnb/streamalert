from stream_alert.config import load_config
from stream_alert.parsers import get_parser
import zlib

from nose.tools import (
    assert_equal,
    assert_not_equal,
    nottest,
    assert_raises,
    raises
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
        """Multi-layered JSON"""
        # setup
        schema = {
            'name': 'string',
            'result': 'string'
        }
        options = {
            "hints": {
                "records": "$.profiles.controls[*]"
            }
        }
        data = '{"profiles": {"controls": [{"name": "infra-test-1", "result": "fail"}]}}'

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema, options=options)

        assert_equal(len(parsed_data), 1)
        assert_equal(parsed_data[0]['result'], 'fail')

    def test_cloudtrail(self):
        """Cloudtrail JSON"""
        schema = self.config['logs']['test_cloudtrail']['schema']
        options = { "hints" : self.config['logs']['test_cloudtrail']['hints'] }
        # load fixture file
        with open('test/unit/fixtures/cloudtrail.json', 'r') as fixture_file:
            data = fixture_file.readlines()

        data_record = data[0].strip()
        # setup json parser
        parsed_result = self.parser_helper(data=data_record, schema=schema, options=options)
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
        """Non-nested JSON objects"""
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

class TestCloudWatchParser(object):
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
        self.parser_class = get_parser('gzip-json')

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

    def test_cloudwatch(self):
        """CloudWatch JSON"""
        schema = self.config['logs']['test_cloudwatch']['schema']
        options = { "hints": self.config['logs']['test_cloudwatch']['hints']}
        with open('test/unit/fixtures/cloudwatch.json','r') as fixture_file:
            data = fixture_file.readlines()
        data_record = zlib.compress(data[0].strip())
        parsed_result = self.parser_helper(data=data_record, schema=schema, options=options)
        assert_not_equal(parsed_result, False)
        assert_equal(80,len(parsed_result))
        for result in parsed_result:
            assert_equal(sorted((u'protocol', u'source', u'destination', u'srcport', u'destport', u'eni', u'action', u'packets', u'bytes', u'windowstart', u'windowend', u'version', u'account', u'flowlogstatus',u'envelope')), sorted(result.keys()))
            assert_equal(sorted((u"logGroup",u"logStream",u"owner")),sorted(result['envelope'].keys()))

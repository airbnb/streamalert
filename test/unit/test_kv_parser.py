from stream_alert.rule_processor.config import load_config
from stream_alert.rule_processor.parsers import get_parser
import zlib

from nose.tools import (
    assert_equal,
    assert_not_equal,
    nottest,
    assert_raises,
    raises
)

class TestKVParser(object):
    def setup(self):
        """Setup before each method"""
        # load config
        self.config = load_config('test/unit/conf')
        # load JSON parser class
        self.parser_class = get_parser('kv')

    def teardown(self):
        """Teardown after each method"""
        pass

    def parser_helper(self, **kwargs):
        data = kwargs['data']
        schema = kwargs['schema']
        options = kwargs['options']

        kv_parser = self.parser_class(data, schema, options)
        parsed_result = kv_parser.parse()
        return parsed_result

    def test_kv_parsing(self):
        """Parse KV - 'key:value,key:value'"""
        # setup
        schema = {
            'name': 'string',
            'result': 'string'
        }
        options = {
            'separator': ':',
            'delimiter': ',',
            'service': 'kinesis'
        }
        data = 'name:joe bob,result:success'

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema, options=options)

        assert_equal(len(parsed_data), 1)
        assert_equal(parsed_data[0]['name'], 'joe bob')

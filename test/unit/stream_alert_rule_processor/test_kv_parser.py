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
from nose.tools import assert_equal

from stream_alert.rule_processor.config import load_config
from stream_alert.rule_processor.parsers import get_parser


class TestKVParser(object):
    """Test class for KVParser"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        # load config
        cls.config = load_config('test/unit/conf')
        # load JSON parser class
        cls.parser_class = get_parser('kv')

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

        kv_parser = self.parser_class(options)
        parsed_result = kv_parser.parse(schema, data)
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
        }
        data = 'name:joe bob,result:success'

        # get parsed data
        parsed_data = self.parser_helper(data=data, schema=schema, options=options)

        assert_equal(len(parsed_data), 1)
        assert_equal(parsed_data[0]['name'], 'joe bob')

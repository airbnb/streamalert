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
import zlib

from nose.tools import assert_equal, assert_not_equal

from stream_alert.rule_processor.config import load_config
from stream_alert.rule_processor.parsers import get_parser


class TestGzipJsonParser(object):
    """Test class for GZIP JSON parser"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        # load config
        cls.config = load_config('test/unit/conf')
        # load JSON parser class
        cls.parser_class = get_parser('gzip-json')

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

    def test_cloudwatch(self):
        """Parse CloudWatch JSON"""
        schema = self.config['logs']['test_cloudwatch']['schema']
        options = self.config['logs']['test_cloudwatch']['configuration']

        with open('test/unit/fixtures/cloudwatch.json', 'r') as fixture_file:
            data = fixture_file.readlines()
        data_record = zlib.compress(data[0].strip())

        parsed_result = self.parser_helper(data=data_record,
                                           schema=schema,
                                           options=options)

        assert_not_equal(parsed_result, False)
        assert_equal(80, len(parsed_result))

        expected_keys = (u'protocol', u'source', u'destination', u'srcport',
                         u'destport', u'eni', u'action', u'packets', u'bytes',
                         u'windowstart', u'windowend', u'version', u'account',
                         u'flowlogstatus', u'streamalert:envelope_keys')
        expected_envelope_keys = (u'logGroup', u'logStream', u'owner')

        for result in parsed_result:
            assert_equal(sorted(expected_keys), sorted(result.keys()))
            assert_equal(sorted(expected_envelope_keys),
                         sorted(result['streamalert:envelope_keys'].keys()))

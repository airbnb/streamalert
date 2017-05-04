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

class TestGzipJsonParser(object):
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

        json_parser = self.parser_class(options)
        parsed_result = json_parser.parse(schema, data)
        return parsed_result

    def test_cloudwatch(self):
        """Parse CloudWatch JSON"""
        schema = self.config['logs']['test_cloudwatch']['schema']
        options = self.config['logs']['test_cloudwatch']['configuration']

        with open('test/unit/fixtures/cloudwatch.json','r') as fixture_file:
            data = fixture_file.readlines()
        data_record = zlib.compress(data[0].strip())

        parsed_result = self.parser_helper(data=data_record,
                                           schema=schema,
                                           options=options)

        assert_not_equal(parsed_result, False)
        assert_equal(80,len(parsed_result))

        expected_keys = (u'protocol', u'source', u'destination', u'srcport',
                         u'destport', u'eni', u'action', u'packets', u'bytes',
                         u'windowstart', u'windowend', u'version', u'account',
                         u'flowlogstatus',u'stream_log_envelope')
        expected_envelope_keys = (u'logGroup', u'logStream', u'owner')

        for result in parsed_result:
            assert_equal(sorted(expected_keys), sorted(result.keys()))
            assert_equal(sorted(expected_envelope_keys),sorted(result['stream_log_envelope'].keys()))

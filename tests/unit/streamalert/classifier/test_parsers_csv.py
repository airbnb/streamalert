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
from collections import OrderedDict
import json

from nose.tools import assert_equal

from stream_alert.classifier.parsers import CSVParser, ParseResult
from stream_alert.shared.config import load_config


class TestCSVParser(object):
    """Test class for CSVParser"""
    # pylint: disable=attribute-defined-outside-init,no-self-use

    def setup(self):
        self.config = load_config('tests/unit/conf')

    @classmethod
    def _default_schema(cls):
        return OrderedDict([('host', 'string'), ('date', 'string'), ('message', 'string')])

    def test_basic_parsing(self):
        """CSV Parser - Basic CSV data"""
        options = {
            'schema': self._default_schema(),
            'configuration': {
                'delimiter': ','
            }
        }
        data = 'test-01.stg.foo.net,01-01-2018,test message!!!!'

        # get parsed data
        parser = CSVParser(options)
        result = parser.parse(data)
        assert_equal(result, True)

        expected_result = [
            {
                'date': '01-01-2018',
                'host': 'test-01.stg.foo.net',
                'message': 'test message!!!!'
            }
        ]
        assert_equal(parser.parses, expected_result)


    def test_csv_parsing_space_delimited(self):
        """CSV Parser - Space separated data"""
        options = {
            'schema': self._default_schema(),
            'configuration': {
                'delimiter': ' '
            }
        }
        data = 'test-01.stg.foo.net 02-02-2018 "test message!!!!"'

        # get parsed data
        parser = CSVParser(options)
        result = parser.parse(data)
        assert_equal(result, True)

        expected_result = [
            {
                'date': '02-02-2018',
                'host': 'test-01.stg.foo.net',
                'message': 'test message!!!!'
            }
        ]
        assert_equal(parser.parses, expected_result)

    def test_csv_parsing_alt_quoted(self):
        """CSV Parser - Single Quoted Field"""
        options = {
            'schema': self._default_schema(),
            'configuration': {
                'quotechar': '\''
            }
        }
        data = ('test-host,datetime-value,\'CREATE TABLE test ( id '
                'INTEGER, type VARCHAR(64) NOT NULL)\'')

        # get parsed data
        parser = CSVParser(options)
        result = parser.parse(data)
        assert_equal(result, True)

        expected_result = [
            {
                'host': 'test-host',
                'date': 'datetime-value',
                'message': 'CREATE TABLE test ( id INTEGER, type VARCHAR(64) NOT NULL)'
            }
        ]

        assert_equal(parser.parses, expected_result)

    def test_csv_parsing_from_json(self):
        """CSV Parser - CSV within JSON"""
        options = {
            'schema': self._default_schema(),
            'configuration': {
                'envelope_keys': {
                    'env_key_01': 'string',
                    'env_key_02': 'string'
                },
                'json_path': 'logEvents[*].message'
            }
        }

        data = json.dumps({
            'env_key_01': 'DATA_MESSAGE',
            'env_key_02': '123456789012',
            'logEvents': [
                {
                    'uuid': '0F08CD2B-F21D-4F3A-9231-B527AD42AB91',
                    'message': 'host-name,01-01-2018,contents'
                },
                {
                    'uuid': '0F08CD2B-F21D-4F3A-9231-B527AD42AB91',
                    'message': 'host-name-02,02-02-2018,contents-02'
                }
            ]
        })

        # get parsed data
        parser = CSVParser(options)
        result = parser.parse(data)
        assert_equal(result, True)

        expected_result = [
            {
                'host': 'host-name',
                'date': '01-01-2018',
                'message': 'contents',
                'streamalert:envelope_keys': {
                    'env_key_01': 'DATA_MESSAGE',
                    'env_key_02': '123456789012'
                }
            },
            {
                'host': 'host-name-02',
                'date': '02-02-2018',
                'message': 'contents-02',
                'streamalert:envelope_keys': {
                    'env_key_01': 'DATA_MESSAGE',
                    'env_key_02': '123456789012'
                }
            }
        ]

        assert_equal(parser.parses, expected_result)

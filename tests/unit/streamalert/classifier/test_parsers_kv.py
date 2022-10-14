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
from collections import OrderedDict

from streamalert.classifier.parsers import KVParser


class TestKVParser:
    """Test class for KVParser"""
    # pylint: disable=no-self-use,protected-access

    def test_parse(self):
        """KV Parser - Parse"""
        options = {
            'schema': {
                'name': 'string',
                'result': 'string'
            },
            'configuration': {
                'separator': ':',
                'delimiter': ',',
            }
        }
        data = 'name:joe bob,result:success'

        # get parsed data
        parser = KVParser(options)
        result = parser.parse(data)
        assert result

        expected_result = [
            {
                'name': 'joe bob',
                'result': 'success'
            }
        ]

        assert parser.parsed_records == expected_result

    def test_extract_record_invalid_field_count(self):
        """KV Parser - Extract Record, Invalid Field Count"""
        options = {
            'schema': {
                'name': 'string',
                'result': 'string'
            }
        }
        data = 'name=foo'

        # get parsed data
        parser = KVParser(options)
        assert parser._extract_record(data) == False

    def test_extract_record_duplicate_fields(self):
        """KV Parser - Extract Record, Duplicate Fields"""
        options = {
            'schema': OrderedDict([('name', 'string'), ('result', 'string'), ('test', 'string')])
        }
        data = 'name=foo result=bar name=baz'

        # get parsed data
        parser = KVParser(options)
        result = parser._extract_record(data)

        expected_result = {
            'name': 'foo',
            'result': 'bar',
            'test': 'baz'
        }

        assert result == expected_result

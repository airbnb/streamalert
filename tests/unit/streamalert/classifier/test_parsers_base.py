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
import json

from mock import patch
from nose.tools import assert_equal

import streamalert.classifier.parsers as parsers
from streamalert.classifier.parsers import ParserBase


class TestParserBaseConfiguration:
    """Test class for ParserBase properties"""
    # pylint: disable=protected-access,no-self-use

    @patch.object(ParserBase, '__abstractmethods__', frozenset())
    def setup(self):
        """Setup before each method"""
        # pylint: disable=abstract-class-instantiated,attribute-defined-outside-init
        options = {
            'schema': {
                'timestamp': 'string',
                'host': 'string'
            },
            'configuration': {
                'optional_top_level_keys': [
                    'host'
                ],
                'log_patterns': {
                    'host': [
                        'foo*'
                    ]
                },
                'json_path': 'logEvents[].message',
                'envelope_keys': {
                    'env_key_01': 'string'
                },
                'optional_envelope_keys': [
                    'env_key_01'
                ]
            }
        }
        self._parser = ParserBase(options)

    def test_schema_property(self):
        """ParserBase - Schema Property"""
        expected_result = {
            'timestamp': 'string',
            'host': 'string'
        }
        assert_equal(self._parser._schema, expected_result)

    def test_optional_top_level_keys_property(self):
        """ParserBase - Optional Top Level Keys Property"""
        expected_result = {'host'}
        assert_equal(self._parser._optional_top_level_keys, expected_result)

    def test_log_patterns_property(self):
        """ParserBase - Log Patterns Property"""
        expected_result = {
            'host': [
                'foo*'
            ]
        }
        assert_equal(self._parser._log_patterns, expected_result)

    def test_json_path_property(self):
        """ParserBase - JSON Path Property"""
        assert_equal(self._parser._json_path, 'logEvents[].message')

    def test_envelope_schema_property(self):
        """ParserBase - Envelope Schema Property"""
        expected_result = {
            'env_key_01': 'string'
        }
        assert_equal(self._parser._envelope_schema, expected_result)

    def test_optional_envelope_keys_property(self):
        """ParserBase - Optional Envelope Keys Property"""
        expected_result = {'env_key_01'}
        assert_equal(self._parser._optional_envelope_keys, expected_result)


class TestParserBaseClassMethods:
    """Test class for ParserBase classmethods"""
    # pylint: disable=protected-access,no-self-use,too-many-public-methods

    def test_default_optional_values_str(self):
        """ParserBase - Default Optional Type, Str"""
        assert_equal(ParserBase.default_optional_values('string'), '')

    def test_default_optional_values_int(self):
        """ParserBase - Default Optional Type, Int"""
        assert_equal(ParserBase.default_optional_values('integer'), 0)

    def test_default_optional_values_float(self):
        """ParserBase - Default Optional Type, Float"""
        assert_equal(ParserBase.default_optional_values('float'), 0.0)

    def test_default_optional_values_boolean(self):
        """ParserBase - Default Optional Type, Boolean"""
        assert_equal(ParserBase.default_optional_values('boolean'), False)

    def test_default_optional_values_list(self):
        """ParserBase - Default Optional Type, List"""
        assert_equal(ParserBase.default_optional_values(list()), [])

    def test_default_optional_values_dict(self):
        """ParserBase - Default Optional Type, Dictionary"""
        assert_equal(ParserBase.default_optional_values(dict()), {})

    def test_apply_envelope(self):
        """ParserBase - Apply Envelope"""
        record = {
            'key': 'value'
        }
        envelope = {
            'env_key_01': 'value'
        }

        ParserBase._apply_envelope(record, envelope)

        expected_record = {
            'key': 'value',
            'streamalert:envelope_keys': {
                'env_key_01': 'value'
            }
        }

        assert_equal(record, expected_record)

    def test_apply_envelope_none(self):
        """ParserBase - Apply Envelope, None"""
        record = {
            'key': 'value'
        }

        ParserBase._apply_envelope(record, {})

        assert_equal(record, {'key': 'value'})

    def test_add_optional_keys_none(self):
        """ParserBase - Add Optional Keys, None"""
        schema = {
            'key': 'string'
        }
        record = {
            'key': 'data'
        }
        ParserBase._add_optional_keys(record, schema, None)
        assert_equal(record, {'key': 'data'})

    def test_add_optional_keys(self):
        """ParserBase - Add Optional Keys"""
        schema = {
            'key': 'string',
            'optional_key': 'integer'
        }
        optionals = {'optional_key'}
        record = {
            'key': 'data'
        }
        ParserBase._add_optional_keys(record, schema, optionals)
        assert_equal(record, {'key': 'data', 'optional_key': 0})

    @patch('logging.Logger.debug')
    def test_matches_log_patterns_str(self, log_mock):
        """ParserBase - Matches Log Patterns, Str"""
        record = {
            'key': 'matching pattern'
        }
        patterns = {
            'key': '*pattern'
        }
        assert_equal(ParserBase._matches_log_patterns(record, patterns), True)
        log_mock.assert_any_call('Transforming flat pattern \'%s\' into list', '*pattern')

    def test_matches_log_patterns_list(self):
        """ParserBase - Matches Log Patterns, List"""
        record = {
            'key': 'matching pattern'
        }
        patterns = {
            'key': [
                '*pattern'
            ]
        }
        assert_equal(ParserBase._matches_log_patterns(record, patterns), True)

    def test_matches_log_patterns_none(self):
        """ParserBase - Matches Log Patterns, None"""
        record = {
            'key': 'value'
        }
        assert_equal(ParserBase._matches_log_patterns(record, {}), True)

    def test_matches_log_patterns_nested(self):
        """ParserBase - Matches Log Patterns, Nested"""
        record = {
            'key': {
                'value': {
                    'nest': 'testing pattern'
                }
            }
        }
        patterns = {
            'key': {
                'value': {
                    'nest': [
                        '*pattern'
                    ]
                }
            }
        }
        assert_equal(ParserBase._matches_log_patterns(record, patterns), True)

    @patch('logging.Logger.error')
    def test_matches_log_patterns_invalid_key(self, log_mock):
        """ParserBase - Matches Log Patterns, Invalid Key"""
        record = {
            'key': 'value'
        }
        patterns = {
            'not_key': '*pattern'
        }
        assert_equal(ParserBase._matches_log_patterns(record, patterns), False)
        log_mock.assert_any_call(
            'Declared log pattern key [%s] does exist in record:\n%s', 'not_key', record)

    def test_key_check_no_schema(self):
        """ParserBase - Key Check, No Schema"""
        assert_equal(ParserBase._key_check(None, {}), True)

    @patch('logging.Logger.debug')
    def test_key_check_bad_envelope_subset(self, log_mock):
        """ParserBase - Key Check, Invalid Envelope Subset"""
        envelope_schema = {
            'env_key_01': 'string'
        }
        record = {
            'env_key_02': 'test'
        }
        assert_equal(ParserBase._key_check(record, envelope_schema, is_envelope=True), False)
        log_mock.assert_called_with('Missing keys in record envelope: %s', {'env_key_01'})

    @patch('logging.Logger.debug')
    def test_key_check_mismatch(self, log_mock):
        """ParserBase - Key Check, Mismatch"""
        schema = {
            'key': 'string'
        }
        record = {
            'not_key': 'test'
        }
        assert_equal(ParserBase._key_check(record, schema), False)
        log_mock.assert_called_with('Found keys not expected in record: %s', 'not_key')

    @patch('logging.Logger.debug')
    def test_key_check_mismatch_non_str_key(self, log_mock):
        """ParserBase - Key Check, Mismatch; Non-String Key"""
        schema = {
            'key': 'string'
        }
        record = {
            100: 'test',
            200: 'test'
        }
        assert_equal(ParserBase._key_check(record, schema), False)
        log_mock.assert_called_with('Found keys not expected in record: %s', '100, 200')

    def test_key_check_nested(self):
        """ParserBase - Key Check, Nested"""
        schema = {
            'key': 'string',
            'nested': {
                'key_01': 'string'
            }
        }
        record = {
            'key': 'value',
            'nested': {
                'key_01': 'value'
            }
        }
        assert_equal(ParserBase._key_check(record, schema), True)

    @patch('logging.Logger.debug')
    def test_key_check_nested_invalid(self, log_mock):
        """ParserBase - Key Check, Invalid Nested"""
        schema = {
            'key': 'string',
            'nested': {
                'key_02': 'integer'
            }
        }
        record = {
            'key': 'value',
            'nested': {
                'key_01': 'value'
            }
        }
        assert_equal(ParserBase._key_check(record, schema), False)
        log_mock.assert_any_call('Expected keys not found in record: %s', 'key_02')

    def test_key_check_nested_loose(self):
        """ParserBase - Key Check, Loose Nested Schema"""
        schema = {
            'key': 'string',
            'nested': {}
        }
        record = {
            'key': 'value',
            'nested': {
                'key_01': 100
            }
        }
        assert_equal(ParserBase._key_check(record, schema), True)

    @patch('logging.Logger.debug')
    def test_key_check_debug(self, log_mock):
        """ParserBase - Key Check, Debug Failure"""
        schema = {
            'key': 'string',
            'nested': {
                'key_02': 'integer'
            }
        }
        record = {
            'key': 'value',
            'nested': {
                'key_01': 100
            }
        }
        with patch.object(parsers, 'LOGGER_DEBUG_ENABLED', True):
            assert_equal(ParserBase._key_check(record, schema), False)
            log_mock.assert_called_with(
                'Nested key check failure. Schema:\n%s\nRecord:\n%s',
                json.dumps(schema, indent=2, sort_keys=True),
                json.dumps(record, indent=2, sort_keys=True)
            )

    def test_convert_type_str(self):
        """ParserBase - Convert Type, Str"""
        schema = {
            'key': 'string'
        }
        record = {
            'key': 100
        }
        assert_equal(ParserBase._convert_type(record, schema), True)
        assert_equal(record, {'key': '100'})

    def test_convert_type_unicode_str(self):
        """ParserBase - Convert Type, Unicode Str"""
        schema = {
            'key': 'string'
        }
        record = {
            'key': '\ue82a'
        }
        assert_equal(ParserBase._convert_type(record, schema), True)
        assert_equal(record, {'key': '\ue82a'})

    def test_convert_type_int(self):
        """ParserBase - Convert Type, Int"""
        schema = {
            'key': 'integer'
        }
        record = {
            'key': '100'
        }
        assert_equal(ParserBase._convert_type(record, schema), True)
        assert_equal(record, {'key': 100})

    def test_convert_type_int_invalid(self):
        """ParserBase - Convert Type, Invalid Int"""
        schema = {
            'key': 'integer'
        }
        record = {
            'key': 'not an int'
        }
        assert_equal(ParserBase._convert_type(record, schema), False)
        assert_equal(record, {'key': 'not an int'})

    def test_convert_type_float(self):
        """ParserBase - Convert Type, Float"""
        schema = {
            'key': 'float'
        }
        record = {
            'key': '0.9'
        }
        assert_equal(ParserBase._convert_type(record, schema), True)
        assert_equal(record, {'key': 0.9})

    def test_convert_type_float_invalid(self):
        """ParserBase - Convert Type, Invalid Float"""
        schema = {
            'key': 'float'
        }
        record = {
            'key': 'not a float'
        }
        assert_equal(ParserBase._convert_type(record, schema), False)
        assert_equal(record, {'key': 'not a float'})

    def test_convert_type_bool(self):
        """ParserBase - Convert Type, Boolean"""
        schema = {
            'key': 'boolean'
        }
        record = {
            'key': 'True'
        }
        assert_equal(ParserBase._convert_type(record, schema), True)
        assert_equal(record, {'key': True})

    def test_convert_type_list(self):
        """ParserBase - Convert Type, Invalid List"""
        schema = {
            'key': []
        }
        record = {
            'key': 'not a list'
        }
        assert_equal(ParserBase._convert_type(record, schema), False)
        assert_equal(record, {'key': 'not a list'})

    @patch('logging.Logger.error')
    def test_convert_type_unsupported_type(self, log_mock):
        """ParserBase - Convert Type, Unsupported Type"""
        schema = {
            'key': 'foobar'
        }
        record = {
            'key': 'foobarbaz'
        }
        assert_equal(ParserBase._convert_type(record, schema), False)
        assert_equal(record, {'key': 'foobarbaz'})
        log_mock.assert_called_with(
            'Unsupported value type in schema for key \'%s\': %s', 'key', 'foobar'
        )

    @patch('logging.Logger.debug')
    def test_convert_type_optionals(self, log_mock):
        """ParserBase - Convert Type, With Optionals Missing"""
        schema = {
            'required_key': 'string',
            'optional_key': 'string'
        }
        optionals = {'optional_key'}
        record = {
            'required_key': 'required_value'
        }
        assert_equal(ParserBase._convert_type(record, schema, optionals), True)
        assert_equal(record, {'required_key': 'required_value'})
        log_mock.assert_called_with(
            'Skipping optional key not found in record: %s', 'optional_key')

    @patch('logging.Logger.debug')
    def test_convert_type_none(self, log_mock):
        """ParserBase - Convert Type, NoneType Value"""
        schema = {
            'key': 'string'
        }
        record = {
            'key': None
        }
        assert_equal(ParserBase._convert_type(record, schema), True)
        assert_equal(record, {'key': None})
        log_mock.assert_called_with('Skipping NoneType value in record for key: %s', 'key')

    def test_convert_type_nested(self):
        """ParserBase - Convert Type, Nested"""
        schema = {
            'key': 'string',
            'nested': {
                'key': 'integer'
            }
        }
        record = {
            'key': 'foo',
            'nested': {
                'key': '100'
            }
        }
        assert_equal(ParserBase._convert_type(record, schema), True)
        assert_equal(record, {'key': 'foo', 'nested': {'key': 100}})


@patch.object(ParserBase, '__abstractmethods__', frozenset())
class TestParserBaseMethods:
    """Test class for ParserBase"""
    # pylint: disable=protected-access,no-self-use,abstract-class-instantiated

    def test_log_schema_type_property(self):
        """ParserBase - Log Schema Type Property"""
        log_type = 'foobar'
        parser = ParserBase(None, log_type)
        assert_equal(parser.log_schema_type, log_type)

    def test_valid_property(self):
        """ParserBase - Valid Property"""
        parser = ParserBase(None)
        parser._valid_parses.append('foobar')
        assert_equal(parser.valid, True)

    def test_valid_property_false(self):
        """ParserBase - Valid Property"""
        parser = ParserBase(None)
        assert_equal(parser.valid, False)

    def test_parses_property(self):
        """ParserBase - Parses Property"""
        item = 'foobar'
        parser = ParserBase(None)
        parser._valid_parses.append(item)
        assert_equal(parser.parsed_records, [item])

    def test_invalid_parses_property(self):
        """ParserBase - Invalid Parses Property"""
        item = 'foobar'
        parser = ParserBase(None)
        parser._invalid_parses.append(item)
        assert_equal(parser.invalid_parses, [item])

    def test_validate_schema_all(self):
        """ParserBase - Validate Schema, All Options"""
        options = {
            'schema': {
                'timestamp': 'string',
                'host': 'string',
                'application': 'string',
                'message': 'string'
            },
            'configuration': {
                'envelope_keys': {
                    'env_key_01': 'string',
                    'env_key_02': 'string'
                },
                'optional_envelope_keys': [
                    'env_key_01'
                ],
                'optional_top_level_keys': [
                    'host'
                ]
            }
        }

        parser = ParserBase(options)
        assert_equal(parser._validate_schema(), True)

    def test_validate_schema_top_level(self):
        """ParserBase - Validate Schema, Top Level"""
        options = {
            'schema': {
                'timestamp': 'string',
                'host': 'string',
                'application': 'string',
                'message': 'string'
            },
            'configuration': {
                'optional_top_level_keys': [
                    'host'
                ]
            }
        }

        parser = ParserBase(options)
        assert_equal(parser._validate_schema(), True)

    def test_validate_schema_invalid(self):
        """ParserBase - Validate Schema, Invalid"""
        options = {
            'schema': {
                'timestamp': 'string',
                'host': 'string',
                'application': 'string',
                'message': 'string'
            },
            'configuration': {
                'optional_top_level_keys': [
                    'date'
                ]
            }
        }

        parser = ParserBase(options)
        assert_equal(parser._validate_schema(), False)

    def test_add_parse_result(self):
        """ParserBase - Add Parse Result, Valid"""
        parser = ParserBase(None)
        record = {
            'key': 'value'
        }
        parser._add_parse_result(record, True, None)
        assert_equal(parser._valid_parses, [record])

    def test_add_parse_result_invalid(self):
        """ParserBase - Add Parse Result, Valid"""
        parser = ParserBase(None)
        record = {
            'key': 'value'
        }
        parser._add_parse_result(record, False, None)
        assert_equal(parser._invalid_parses, [record])

    def test_extract_envelope(self):
        """ParserBase - Extract Envelope"""
        options = {
            'configuration': {
                'envelope_keys': [
                    'env_key_01'
                ]
            }
        }
        record = {
            'env_key_01': 'foo',
            'non_env_key': 'bar'
        }

        parser = ParserBase(options)
        envelope = parser._extract_envelope(record)
        assert_equal(envelope, {'env_key_01': 'foo'})

    def test_extract_envelope_none(self):
        """ParserBase - Extract Envelope, None"""
        record = {
            'key': 'value'
        }

        parser = ParserBase(None)
        envelope = parser._extract_envelope(record)
        assert_equal(envelope, None)

    def test_json_path_records(self):
        """ParserBase - JSON Path Records"""
        expected_records = [
            {
                'foo': 'bar'
            },
            {
                'bar': 'baz'
            }
        ]
        record = {
            'key': [
                {
                    'value': expected_records
                }
            ]
        }
        options = {
            'configuration': {
                'json_path': 'key[].value[]'
            }
        }

        parser = ParserBase(options)
        records = parser._json_path_records(record)
        assert_equal(records, expected_records)

    def test_parse(self):
        """ParserBase - Parse, Invalid Schema"""
        options = {
            'schema': {
                'key': 'string'
            },
            'configuration': {
                'optional_top_level_keys': [
                    'non_key'
                ]
            }
        }

        assert_equal(ParserBase(options).parse(None), False)

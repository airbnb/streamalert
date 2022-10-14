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
from unittest.mock import Mock

from streamalert.classifier.payload.payload_base import PayloadRecord


class TestPayloadRecord:
    """PayloadRecord tests"""
    # pylint: disable=no-self-use,protected-access

    def setup(self):
        """PayloadRecord - Setup"""
        # pylint: disable=attribute-defined-outside-init
        self._record = {'key': 'value'}
        self._payload_record = PayloadRecord(self._record)

    @classmethod
    def _mock_parser(cls, records=None, invalid_records=None):
        return Mock(parsed_records=records or [], invalid_parses=invalid_records or [],
                    log_schema_type='foo:bar', __nonzero__=lambda: records is not None)

    def test_non_zero_false(self):
        """PayloadRecord - Non Zero/Bool, False"""
        assert not bool(self._payload_record)

    def test_non_zero_true(self):
        """PayloadRecord - Non Zero/Bool, True"""
        self._payload_record._parser = self._mock_parser(records=['foobarbaz'])
        assert bool(self._payload_record)

    def test_len_str(self):
        """PayloadRecord - Length, Str Data"""
        self._payload_record._record_data = 'foobar'
        assert len(self._payload_record) == 6

    def test_len_dict(self):
        """PayloadRecord - Length, Dict Data"""
        assert len(self._payload_record) == 15

    def test_repr(self):
        """PayloadRecord - Repr"""
        self._payload_record._parser = self._mock_parser(records=[self._record])
        expected_result = (
            '<PayloadRecord valid:True; log type:foo:bar; parsed records:1;>'
        )
        assert repr(self._payload_record) == expected_result

    def test_repr_invalid(self):
        """PayloadRecord - Repr, Invalid"""
        expected_result = '<PayloadRecord valid:False; raw record:{"key": "value"};>'
        assert repr(self._payload_record) == expected_result

    def test_repr_invalid_records(self):
        """PayloadRecord - Repr, Invalid Records"""
        self._payload_record._parser = self._mock_parser(
            records=[self._record],
            invalid_records=[self._record]
        )
        expected_result = (
            '<PayloadRecord valid:True; log type:foo:bar; parsed records:1; invalid records:1 '
            '([{"key": "value"}]); raw record:{"key": "value"};>'
        )
        assert repr(self._payload_record) == expected_result

    def test_data_property(self):
        """PayloadRecord - Data Property"""
        assert self._payload_record.data == self._record

    def test_parser_property(self):
        """PayloadRecord - Parser Property"""
        parser = self._mock_parser()
        self._payload_record._parser = parser
        assert self._payload_record.parser == parser

    def test_parser_property_setter(self):
        """PayloadRecord - Parser Property, Setter"""
        parser = self._mock_parser()
        self._payload_record.parser = parser
        assert self._payload_record._parser == parser

    def test_parsed_records_property(self):
        """PayloadRecord - Parsed Records Property"""
        self._payload_record._parser = self._mock_parser(records=[self._record])
        assert self._payload_record.parsed_records == [self._record]

    def test_parsed_records_property_empty(self):
        """PayloadRecord - Parsed Records Property, Empty"""
        assert self._payload_record.parsed_records == []

    def test_invalid_records_property(self):
        """PayloadRecord - Invalid Records Property"""
        self._payload_record._parser = self._mock_parser(
            records=[self._record],  # the parser must have records to be considered valid at all
            invalid_records=[self._record]
        )
        assert self._payload_record.invalid_records == [self._record]

    def test_invalid_records_property_empty(self):
        """PayloadRecord - Invalid Records Property, Empty"""
        assert self._payload_record.invalid_records == []

    def test_log_schema_type_property(self):
        """PayloadRecord - Log Schema Type"""
        self._payload_record._parser = self._mock_parser(records=[self._record])
        assert self._payload_record.log_schema_type == 'foo:bar'

    def test_log_type_property(self):
        """PayloadRecord - Log Type"""
        self._payload_record._parser = self._mock_parser(records=[self._record])
        assert self._payload_record.log_type == 'foo'

    def test_log_sub_type_property(self):
        """PayloadRecord - Log Sub Type"""
        self._payload_record._parser = self._mock_parser(records=[self._record])
        assert self._payload_record.log_subtype == 'bar'

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
# pylint: disable=protected-access,attribute-defined-outside-init,invalid-name
from datetime import datetime

from mock import MagicMock
from nose.tools import assert_equal, assert_true, assert_false

from publishers.community.generic import _delete_dictionary_fields, StringifyArrays
from stream_alert.alert_processor.helpers import compose_alert
from stream_alert.alert_processor.outputs.output_base import OutputDispatcher
from stream_alert.alert_processor.outputs.slack import SlackOutput
from tests.unit.stream_alert_alert_processor.helpers import get_alert


class TestPublishersForOutput(object):

    @staticmethod
    def test_publisher_for_output():
        alert = get_alert(context={'context': 'value'})
        alert.created = datetime(2019, 1, 1)
        alert.publishers = {
            'slack': 'stream_alert.shared.publisher.DefaultPublisher',
            'slack:unit_test_channel': 'publishers.community.generic.remove_internal_fields',
            'demisto': 'publishers.community.generic.blank',
        }
        output = MagicMock(spec=OutputDispatcher)
        output.__service__ = 'slack'
        descriptor = 'unit_test_channel'

        publication = compose_alert(alert, output, descriptor)

        expectation = {
            'source_entity': 'corp-prefix.prod.cb.region',
            'rule_name': 'cb_binarystore_file_added',
            'created': '2019-01-01T00:00:00.000000Z',
            'log_source': 'carbonblack:binarystore.file.added',
            'log_type': 'json',
            'cluster': '',
            'context': {'context': 'value'},
            'source_service': 's3',
            'id': '79192344-4a6d-4850-8d06-9c3fef1060a4',
            'rule_description': 'Info about this rule and what actions to take',
            'record': {
                'compressed_size': '9982',
                'timestamp': '1496947381.18',
                'node_id': '1',
                'cb_server': 'cbserver',
                'size': '21504',
                'type': 'binarystore.file.added',
                'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
                'md5': '0F9AA55DA3BDE84B35656AD8911A22E1'
            }
        }
        assert_equal(publication, expectation)


class TestDefaultPublisher(object):
    PUBLISHER_NAME = 'stream_alert.shared.publisher.DefaultPublisher'

    def setup(self):
        self._alert = get_alert(context={'context': 'value'})
        self._alert.created = datetime(2019, 1, 1)
        self._alert.publishers = [self.PUBLISHER_NAME]
        self._output = MagicMock(spec=SlackOutput)  # Just use some random output

    def test_default_publisher(self):
        """AlertPublisher - DefaultPublisher - Positive Case"""
        publication = compose_alert(self._alert, self._output, 'test')
        expectation = {
            'publishers': ['stream_alert.shared.publisher.DefaultPublisher'],
            'source_entity': 'corp-prefix.prod.cb.region',
            'outputs': ['slack:unit_test_channel'],
            'cluster': '',
            'rule_description': 'Info about this rule and what actions to take',
            'log_type': 'json',
            'rule_name': 'cb_binarystore_file_added',
            'source_service': 's3',
            'created': '2019-01-01T00:00:00.000000Z',
            'log_source': 'carbonblack:binarystore.file.added',
            'id': '79192344-4a6d-4850-8d06-9c3fef1060a4',
            'record': {
                'compressed_size': '9982',
                'node_id': '1',
                'cb_server': 'cbserver',
                'timestamp': '1496947381.18',
                'md5': '0F9AA55DA3BDE84B35656AD8911A22E1',
                'type': 'binarystore.file.added',
                'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
                'size': '21504'
            },
            'context': {'context': 'value'},
            'staged': False
        }
        assert_equal(publication, expectation)


class TestRecordPublisher(object):
    PUBLISHER_NAME = 'publishers.community.generic.add_record'

    def setup(self):
        self._alert = get_alert(context={'context': 'value'})
        self._alert.created = datetime(2019, 1, 1)
        self._alert.publishers = [self.PUBLISHER_NAME]
        self._output = MagicMock(spec=SlackOutput)  # Just use some random output

    def test_default_publisher(self):
        """AlertPublisher - add_record - Positive Case"""
        publication = compose_alert(self._alert, self._output, 'test')
        expectation = {
            'record': {
                'compressed_size': '9982',
                'node_id': '1',
                'cb_server': 'cbserver',
                'timestamp': '1496947381.18',
                'md5': '0F9AA55DA3BDE84B35656AD8911A22E1',
                'type': 'binarystore.file.added',
                'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
                'size': '21504'
            },
        }
        assert_equal(publication, expectation)


class TestRemoveInternalFieldsPublisher(object):
    PUBLISHER_NAME = 'publishers.community.generic.remove_internal_fields'

    def setup(self):
        self._alert = get_alert(context={'context': 'value'})
        self._alert.created = datetime(2019, 1, 1)
        self._alert.publishers = [TestDefaultPublisher.PUBLISHER_NAME, self.PUBLISHER_NAME]
        self._output = MagicMock(spec=SlackOutput)  # Just use some random output

    def test_remove_internal_fields(self):
        """AlertPublisher - remove_internal_fields"""
        publication = compose_alert(self._alert, self._output, 'test')

        expectation = {
            'source_entity': 'corp-prefix.prod.cb.region',
            'rule_name': 'cb_binarystore_file_added',
            'source_service': 's3',
            'created': '2019-01-01T00:00:00.000000Z',
            'log_source': 'carbonblack:binarystore.file.added',
            'id': '79192344-4a6d-4850-8d06-9c3fef1060a4',
            'cluster': '',
            'context': {'context': 'value'},
            'record': {
                'compressed_size': '9982',
                'timestamp': '1496947381.18',
                'node_id': '1',
                'cb_server': 'cbserver',
                'md5': '0F9AA55DA3BDE84B35656AD8911A22E1',
                'type': 'binarystore.file.added',
                'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
                'size': '21504'
            },
            'log_type': 'json',
            'rule_description': 'Info about this rule and what actions to take'
        }
        assert_equal(publication, expectation)


class TestRemoveStreamAlertNormalizationFields(object):
    PUBLISHER_NAME = 'publishers.community.generic.remove_streamalert_normalization'

    def setup(self):
        self._alert = get_alert(context={'context': 'value'})
        self._alert.created = datetime(2019, 1, 1)
        self._alert.record['added_fields'] = {
            'streamalert': {
                'yay': 'no',
            },
            'oof': [
                {
                    'streamalert:normalization': '/////',
                    'other': 'key'
                }
            ],
            'streamalert:normalization': {
                'bunch of stuff': 'that does not belong'
            },
        }
        self._alert.publishers = [TestDefaultPublisher.PUBLISHER_NAME, self.PUBLISHER_NAME]
        self._output = MagicMock(spec=SlackOutput)  # Just use some random output

    def test_works(self):
        """AlertPublisher - FilterFields - Nothing"""
        publication = compose_alert(self._alert, self._output, 'test')

        expectation = {
            'staged': False,
            'publishers': [
                'stream_alert.shared.publisher.DefaultPublisher',
                'publishers.community.generic.remove_streamalert_normalization'
            ],
            'source_entity': 'corp-prefix.prod.cb.region',
            'rule_name': 'cb_binarystore_file_added',
            'outputs': ['slack:unit_test_channel'],
            'created': '2019-01-01T00:00:00.000000Z',
            'log_source': 'carbonblack:binarystore.file.added',
            'log_type': 'json', 'cluster': '',
            'context': {'context': 'value'},
            'source_service': 's3',
            'id': '79192344-4a6d-4850-8d06-9c3fef1060a4',
            'rule_description': 'Info about this rule and what actions to take',
            'record': {
                'compressed_size': '9982',
                'added_fields': {
                    'streamalert': {'yay': 'no'},
                    'oof': [{'other': 'key'}],
                },
                'timestamp': '1496947381.18',
                'node_id': '1',
                'cb_server': 'cbserver',
                'size': '21504',
                'type': 'binarystore.file.added',
                'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
                'md5': '0F9AA55DA3BDE84B35656AD8911A22E1'
            }
        }
        assert_equal(publication, expectation)


class TestEnumerateFields(object):
    PUBLISHER_NAME = 'publishers.community.generic.enumerate_fields'

    def setup(self):
        self._alert = get_alert(context={
            'context1': 'value',
            'attribs': [
                {'type': 'Name', 'value': 'Bob'},
                {'type': 'Age', 'value': '42'},
                {'type': 'Profession', 'value': 'Software engineer'},
            ]
        })
        self._alert.created = datetime(2019, 1, 1)
        self._alert.publishers = [TestDefaultPublisher.PUBLISHER_NAME, self.PUBLISHER_NAME]
        self._output = MagicMock(spec=SlackOutput)  # Just use some random output

    def test_enumerate_fields(self):
        """AlertPublisher - enumerate_fields"""
        publication = compose_alert(self._alert, self._output, 'test')

        expectation = {
            'cluster': '',
            'context.context1': 'value',
            'context.attribs[0].type': 'Name',
            'context.attribs[0].value': 'Bob',
            'context.attribs[1].type': 'Age',
            'context.attribs[1].value': '42',
            'context.attribs[2].value': 'Software engineer',
            'context.attribs[2].type': 'Profession',
            'created': '2019-01-01T00:00:00.000000Z',
            'id': '79192344-4a6d-4850-8d06-9c3fef1060a4',
            'log_source': 'carbonblack:binarystore.file.added',
            'log_type': 'json',
            'outputs[0]': 'slack:unit_test_channel',
            'publishers[0]': 'stream_alert.shared.publisher.DefaultPublisher',
            'publishers[1]': 'publishers.community.generic.enumerate_fields',
            'record.timestamp': '1496947381.18',
            'record.compressed_size': '9982',
            'record.cb_server': 'cbserver',
            'record.file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
            'record.md5': '0F9AA55DA3BDE84B35656AD8911A22E1',
            'record.node_id': '1',
            'record.size': '21504',
            'record.type': 'binarystore.file.added',
            'rule_description': 'Info about this rule and what actions to take',
            'rule_name': 'cb_binarystore_file_added',
            'source_entity': 'corp-prefix.prod.cb.region',
            'source_service': 's3',
            'staged': False,
        }
        assert_equal(publication, expectation)

    def test_enumerate_fields_alphabetical_order(self):
        """AlertPublisher - enumerate_fields - enforce alphabetical order"""
        publication = compose_alert(self._alert, self._output, 'test')

        expectation = [
            'cluster',
            'context.attribs[0].type',
            'context.attribs[0].value',
            'context.attribs[1].type',
            'context.attribs[1].value',
            'context.attribs[2].type',
            'context.attribs[2].value',
            'context.context1',
            'created',
            'id',
            'log_source',
            'log_type',
            'outputs[0]',
            'publishers[0]',
            'publishers[1]',
            'record.cb_server',
            'record.compressed_size',
            'record.file_path',
            'record.md5',
            'record.node_id',
            'record.size',
            'record.timestamp',
            'record.type',
            'rule_description',
            'rule_name',
            'source_entity',
            'source_service',
            'staged',
        ]

        assert_equal(publication.keys(), expectation)


def test_delete_dictionary_fields():
    """Generic - _delete_dictionary_fields"""
    pub = {
        'level1-1': {
            'level2-1': [
                {
                    'level3-1': 'level4',
                    'level3-2': 'level4',
                }
            ],
            'level2-2': {
                'level3': 'level4',
            }
        },
        'level1-2': [
            {
                'thereisno': 'spoon'
            }
        ]
    }

    result = _delete_dictionary_fields(pub, '^level3-1$')

    expectation = {
        'level1-1': {
            'level2-1': [
                {
                    'level3-2': 'level4',
                }
            ],
            'level2-2': {
                'level3': 'level4',
            }
        },
        'level1-2': [
            {
                'thereisno': 'spoon'
            }
        ]
    }

    assert_equal(result, expectation)


class TestRemoveFields(object):
    PUBLISHER_NAME = 'publishers.community.generic.remove_fields'

    def setup(self):
        self._alert = get_alert(context={
            'remove_fields': [
                'streamalert', '^publishers', 'type$',
                '^outputs$', '^cluster$', '^context$'
            ]
        })
        self._alert.created = datetime(2019, 1, 1)
        self._alert.publishers = [TestDefaultPublisher.PUBLISHER_NAME, self.PUBLISHER_NAME]
        self._output = MagicMock(spec=SlackOutput)  # Just use some random output

    def test_remove_fields(self):
        """AlertPublisher - enumerate_fields - enforce alphabetical order"""
        publication = compose_alert(self._alert, self._output, 'test')

        expectation = {
            'staged': False,
            'source_entity': 'corp-prefix.prod.cb.region',
            'rule_name': 'cb_binarystore_file_added',
            'created': '2019-01-01T00:00:00.000000Z',
            'log_source': 'carbonblack:binarystore.file.added',
            'source_service': 's3',
            'id': '79192344-4a6d-4850-8d06-9c3fef1060a4',
            'rule_description': 'Info about this rule and what actions to take',
            'record': {
                'compressed_size': '9982',
                'timestamp': '1496947381.18',
                'node_id': '1',
                'cb_server': 'cbserver',
                'size': '21504',
                'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
                'md5': '0F9AA55DA3BDE84B35656AD8911A22E1'
            }
        }

        assert_equal(publication, expectation)


class TestPopulateFields(object):
    PUBLISHER_NAME = 'publishers.community.generic.populate_fields'

    def setup(self):
        self._alert = get_alert(context={
            'populate_fields': [
                'compressed_size', 'id', 'oof', 'multi_field'
            ],
            'other_field': 'a',
            'container': {
                'multi_field': 1,
                'depth2': {
                    'multi_field': 2,
                }
            }
        })
        self._alert.created = datetime(2019, 1, 1)
        self._alert.publishers = [TestDefaultPublisher.PUBLISHER_NAME, self.PUBLISHER_NAME]
        self._output = MagicMock(spec=SlackOutput)  # Just use some random output

    def test_remove_fields(self):
        """AlertPublisher - populate_fields"""
        publication = compose_alert(self._alert, self._output, 'test')

        expectation = {
            'compressed_size': ['9982'],
            'oof': [],
            'id': ['79192344-4a6d-4850-8d06-9c3fef1060a4'],
            'multi_field': [1, 2]
        }

        assert_equal(publication, expectation)


class TestStringifyArrays(object):
    PUBLISHER_NAME = 'publishers.community.generic.StringifyArrays'

    def setup(self):
        self._alert = get_alert(context={
            'array': ['a', 'b', 'c'],
            'not_array': ['a', {'b': 'c'}, 'd'],
            'nest': {
                'deep_array': ['a', 'b', 'c'],
            }
        })
        self._alert.created = datetime(2019, 1, 1)
        self._alert.publishers = [TestDefaultPublisher.PUBLISHER_NAME, self.PUBLISHER_NAME]
        self._output = MagicMock(spec=SlackOutput)  # Just use some random output

    def test_publish(self):
        """AlertPublisher - StringifyArrays - publish"""
        publication = compose_alert(self._alert, self._output, 'test')

        expectation = {
            'not_array': ['a', {'b': 'c'}, 'd'],
            'array': 'a\nb\nc',
            'nest': {'deep_array': 'a\nb\nc'}
        }

        assert_equal(publication['context'], expectation)


def test_stringifyarrays_is_scalar_array_none():
    """AlertPublisher - StringifyArrays - is_scalar_array - None"""
    assert_false(StringifyArrays.is_scalar_array(None))


def test_stringifyarrays_is_scalar_array_dict():
    """AlertPublisher - StringifyArrays - is_scalar_array - Dict"""
    assert_false(StringifyArrays.is_scalar_array({'a': 'b'}))


def test_stringifyarrays_is_scalar_array_string():
    """AlertPublisher - StringifyArrays - is_scalar_array - String"""
    assert_false(StringifyArrays.is_scalar_array('aaa'))


def test_stringifyarrays_is_scalar_array_array_string():
    """AlertPublisher - StringifyArrays - is_scalar_array - Array[str]"""
    assert_true(StringifyArrays.is_scalar_array(['a', 'b']))


def test_stringifyarrays_is_scalar_array_array_int():
    """AlertPublisher - StringifyArrays - is_scalar_array - Array[int]"""
    assert_true(StringifyArrays.is_scalar_array([1, 2]))


def test_stringifyarrays_is_scalar_array_array_mixed():
    """AlertPublisher - StringifyArrays - is_scalar_array - Array[mixed]"""
    assert_true(StringifyArrays.is_scalar_array([1, 'a']))


def test_stringifyarrays_is_scalar_array_array_mixed_invalid():
    """AlertPublisher - StringifyArrays - is_scalar_array - Array[mixed], invalid"""
    assert_false(StringifyArrays.is_scalar_array([1, 'a', {}]))

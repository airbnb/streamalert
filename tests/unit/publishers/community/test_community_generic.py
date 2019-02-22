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
# pylint: disable=protected-access,attribute-defined-outside-init
from datetime import datetime

from mock import MagicMock
from nose.tools import assert_equal

from stream_alert.alert_processor.helpers import publish_alert
from stream_alert.alert_processor.outputs.output_base import OutputDispatcher
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

        publication = publish_alert(alert, output, descriptor)

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

    def test_default_publisher(self):
        """AlertPublisher - DefaultPublisher - Positive Case"""
        publication = publish_alert(self._alert, None, None)
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

    def test_default_publisher(self):
        """AlertPublisher - add_record - Positive Case"""
        publication = publish_alert(self._alert, None, None)
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

    def test_remove_internal_fields(self):
        """AlertPublisher - remove_internal_fields"""

        publication = publish_alert(self._alert, None, None)

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

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

from mock import patch, MagicMock
from nose.tools import assert_true, assert_equal

from stream_alert.alert_processor.outputs.output_base import StreamAlertOutput
from stream_alert.alert_processor.publishers import AlertPublisherRepository, CompositePublisher
from stream_alert.alert_processor.publishers.core import WrappedFunctionPublisher
from stream_alert.alert_processor.publishers.default import (
    DefaultPublisher,
    RemoveInternalFields,
    SamplePublisher1,
    SamplePublisher2
)
from tests.unit.stream_alert_alert_processor.helpers import get_alert


class TestAlertPublisherRepository(object):

    @staticmethod
    def test_registers_default_publishers():
        """AlertPublisher - AlertPublisherRepository - all_publishers()"""
        publishers = AlertPublisherRepository.all_publishers()

        assert_true(len(publishers) > 0)

    @staticmethod
    def test_get_publisher():
        """AlertPublisher - AlertPublisherRepository - get_publisher()"""
        publisher = AlertPublisherRepository.get_publisher('default')  # this one is always defined

        assert_true(isinstance(publisher, DefaultPublisher))

    @staticmethod
    def test_create_composite_publisher():
        """AlertPublisher - AlertPublisherRepository - create_composite_publisher() - Valid"""
        publisher = AlertPublisherRepository.create_composite_publisher([
            'stream_alert.alert_processor.publishers.default.blank',
            'stream_alert.alert_processor.publishers.default.record',
        ])

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 2)

    @staticmethod
    def test_create_composite_publisher_default():
        """AlertPublisher - AlertPublisherRepository - create_composite_publisher() - Default"""
        publisher = AlertPublisherRepository.create_composite_publisher([])

        assert_true(isinstance(publisher, DefaultPublisher))

    @staticmethod
    @patch('logging.Logger.error')
    def test_create_composite_publisher_noexist(error_log):
        """AlertPublisher - AlertPublisherRepository - create_composite_publisher() - No Exist"""
        publisher = AlertPublisherRepository.create_composite_publisher(['no_exist'])

        assert_true(isinstance(publisher, DefaultPublisher))
        error_log.assert_called_with('Designated output service [%s] does not exist', 'no_exist')


class TestAlertPublisherRepositoryAssemblePublisher(object):
    def setup(self):
        self._alert = get_alert(context={'this_context': 'that_value'})
        self._descriptor = 'some_descriptor'
        self._output = StreamAlertOutput.create_dispatcher('demisto', MagicMock())

    def test_assemble_alert_publisher_for_output_none(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - String"""
        self._alert.publishers = None

        publisher = AlertPublisherRepository.assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, DefaultPublisher))

    def test_assemble_alert_publisher_for_output_single_string(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - String"""
        self._alert.publishers = 'stream_alert.alert_processor.publishers.default.blank'

        publisher = AlertPublisherRepository.assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 1)
        assert_true(isinstance(publisher._publishers[0], WrappedFunctionPublisher))

    def test_assemble_alert_publisher_for_output_list_string(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - List of Strings"""
        self._alert.publishers = ['default', 'no_internal']

        publisher = AlertPublisherRepository.assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 2)
        assert_true(isinstance(publisher._publishers[0], DefaultPublisher))
        assert_true(isinstance(publisher._publishers[1], RemoveInternalFields))

    def test_assemble_alert_publisher_for_output_dict_empty(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Empty Dict"""
        self._alert.publishers = {}

        publisher = AlertPublisherRepository.assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, DefaultPublisher))

    def test_assemble_alert_publisher_for_output_dict_irrelevant_key(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Dict with Irrelevant Key"""
        self._alert.publishers = {
            'pagerduty': ['stream_alert.alert_processor.publishers.default.blank']
        }

        publisher = AlertPublisherRepository.assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, DefaultPublisher))

    def test_assemble_alert_publisher_for_output_dict_key_string(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Dict with Key -> String"""
        self._alert.publishers = {
            'demisto': 'stream_alert.alert_processor.publishers.default.blank',
            'pagerduty': ['stream_alert.alert_processor.publishers.default.blank']
        }

        publisher = AlertPublisherRepository.assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 1)
        assert_true(isinstance(publisher._publishers[0], WrappedFunctionPublisher))

    def test_assemble_alert_publisher_for_output_dict_key_array(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Dict with Key -> List"""
        self._alert.publishers = {
            'demisto': ['default', 'no_internal'],
            'pagerduty': ['stream_alert.alert_processor.publishers.default.blank']
        }

        publisher = AlertPublisherRepository.assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 2)

    def test_assemble_alert_publisher_for_output_dict_key_descriptor_string(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Dict matches Desc String"""
        self._alert.publishers = {
            'demisto:some_descriptor': 'no_internal',
            'pagerduty': ['stream_alert.alert_processor.publishers.default.blank']
        }

        publisher = AlertPublisherRepository.assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 1)

    def test_assemble_alert_publisher_for_output_dict_key_descriptor_list(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Dict matches Desc List"""
        self._alert.publishers = {
            'demisto:some_descriptor': ['default', 'no_internal'],
            'pagerduty': ['stream_alert.alert_processor.publishers.default.blank']
        }

        publisher = AlertPublisherRepository.assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 2)

    def test_assemble_alert_publisher_for_output_dict_key_both_descriptor_output_list(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Dict full match Lists"""
        self._alert.publishers = {
            'demisto': ['sample_1', 'sample_2'],
            'demisto:some_descriptor': ['default', 'no_internal'],
            'pagerduty': ['stream_alert.alert_processor.publishers.default.blank']
        }

        publisher = AlertPublisherRepository.assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 4)

        # Order is important
        assert_true(isinstance(publisher._publishers[0], DefaultPublisher))
        assert_true(isinstance(publisher._publishers[1], RemoveInternalFields))
        assert_true(isinstance(publisher._publishers[2], SamplePublisher1))
        assert_true(isinstance(publisher._publishers[3], SamplePublisher2))


class TestCompositePublisher(object):

    @staticmethod
    def test_composite_publisher_ordering():
        publisher = CompositePublisher([
            DefaultPublisher(),
            RemoveInternalFields(),
            SamplePublisher1(),
        ])

        alert = get_alert()
        alert.created = datetime(2019, 01, 01)

        publication = publisher.publish(alert, {})

        expectation = {
            'source_entity': 'corp-prefix.prod.cb.region',
            'rule_name': 'cb_binarystore_file_added',
            'source_service': 's3',
            'created': '2019-01-01T00:00:00.000000Z',
            'log_source': 'carbonblack:binarystore.file.added',
            'sample_1': 'yay, it worked!',
            'id': '79192344-4a6d-4850-8d06-9c3fef1060a4',
            'cluster': '',
            'context': {},
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

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
from mock import patch, MagicMock
from nose.tools import assert_true, assert_equal

from stream_alert.alert_processor.helpers import _assemble_alert_publisher_for_output
from stream_alert.alert_processor.outputs.output_base import StreamAlertOutput
from publishers.core import (
    AlertPublisherRepository,
    WrappedFunctionPublisher,
    CompositePublisher,
    get_unique_publisher_name,
    AlertPublisher,
    BaseAlertPublisher
)
from publishers.community.generic import DefaultPublisher
from tests.unit.stream_alert_alert_processor.helpers import get_alert


@AlertPublisher
class SamplePublisher1(BaseAlertPublisher):

    def publish(self, alert, publication):
        new_publication = publication.copy()
        new_publication['test1'] = True
        return new_publication


@AlertPublisher
class SamplePublisher2(BaseAlertPublisher):

    def publish(self, alert, publication):
        new_publication = publication.copy()
        new_publication['test2'] = True
        return new_publication


@AlertPublisher
class SamplePublisher3(BaseAlertPublisher):

    def publish(self, alert, publication):
        new_publication = publication.copy()
        new_publication['test3'] = True
        return new_publication


@AlertPublisher
def sample_publisher_4(alert, publication):  # pylint: disable=unused-argument
    new_publication = publication.copy()
    new_publication['test4'] = True
    return new_publication


@AlertPublisher
def sample_publisher_blank(alert, publication):  # pylint: disable=unused-argument
    return {}


def test_get_unique_publisher_name_class():
    """AlertPublisher - get_unique_publisher_name() - Class"""

    name = get_unique_publisher_name(SamplePublisher1)
    assert_equal(
        name,
        'tests.unit.stream_alert_alert_processor.test_publishers.test_core.SamplePublisher1'
    )


def test_get_unique_publisher_name_function():
    """AlertPublisher - get_unique_publisher_name() - Function"""

    name = get_unique_publisher_name(sample_publisher_4)
    assert_equal(
        name,
        'tests.unit.stream_alert_alert_processor.test_publishers.test_core.sample_publisher_4'
    )


class TestAlertPublisherRepository(object):

    @staticmethod
    def test_registers_default_publishers():
        """AlertPublisher - AlertPublisherRepository - all_publishers()"""
        publishers = AlertPublisherRepository.all_publishers()

        assert_true(len(publishers) > 0)

    @staticmethod
    def test_get_publisher():
        """AlertPublisher - AlertPublisherRepository - get_publisher() - SamplePublisher1"""
        publisher = AlertPublisherRepository.get_publisher(
            'tests.unit.stream_alert_alert_processor.test_publishers.test_core.SamplePublisher1'
        )

        assert_true(isinstance(publisher, SamplePublisher1))

    @staticmethod
    def test_create_composite_publisher():
        """AlertPublisher - AlertPublisherRepository - create_composite_publisher() - Valid"""
        publisher = AlertPublisherRepository.create_composite_publisher([
            'tests.unit.stream_alert_alert_processor.test_publishers.test_core.SamplePublisher1',
            'tests.unit.stream_alert_alert_processor.test_publishers.test_core.SamplePublisher2',
        ])

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 2)
        assert_true(isinstance(publisher._publishers[0], SamplePublisher1))
        assert_true(isinstance(publisher._publishers[1], SamplePublisher2))

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
        error_log.assert_called_with('Publisher [%s] does not exist', 'no_exist')


class TestAlertPublisherRepositoryAssemblePublisher(object):
    def setup(self):
        self._alert = get_alert(context={'this_context': 'that_value'})
        self._descriptor = 'some_descriptor'
        self._output = StreamAlertOutput.create_dispatcher('demisto', MagicMock())

    def test_assemble_alert_publisher_for_output_none(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - String"""
        self._alert.publishers = None

        publisher = _assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, DefaultPublisher))

    def test_assemble_alert_publisher_for_output_single_string(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - String"""
        self._alert.publishers = ('tests.unit.stream_alert_alert_processor.test_publishers.'
                                  'test_core.SamplePublisher1')

        publisher = _assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 1)
        assert_true(isinstance(publisher._publishers[0], SamplePublisher1))

    def test_assemble_alert_publisher_for_output_list_string(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - List of Strings"""
        self._alert.publishers = [
            'tests.unit.stream_alert_alert_processor.test_publishers.test_core.SamplePublisher1',
            'tests.unit.stream_alert_alert_processor.test_publishers.test_core.SamplePublisher2',
        ]

        publisher = _assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 2)
        assert_true(isinstance(publisher._publishers[0], SamplePublisher1))
        assert_true(isinstance(publisher._publishers[1], SamplePublisher2))

    def test_assemble_alert_publisher_for_output_dict_empty(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Empty Dict"""
        self._alert.publishers = {}

        publisher = _assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, DefaultPublisher))

    def test_assemble_alert_publisher_for_output_dict_irrelevant_key(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Dict with Irrelevant Key"""
        self._alert.publishers = {
            'pagerduty': [
                'tests.unit.stream_alert_alert_processor.test_publishers.test_core.SamplePublisher1'
            ]
        }

        publisher = _assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, DefaultPublisher))

    def test_assemble_alert_publisher_for_output_dict_key_string(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Dict with Key -> String"""
        self._alert.publishers = {
            'demisto': ('tests.unit.stream_alert_alert_processor.test_publishers.'
                        'test_core.SamplePublisher1'),
            'pagerduty': [
                'tests.unit.stream_alert_alert_processor.test_publishers.test_core.SamplePublisher2'
            ]
        }

        publisher = _assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 1)
        assert_true(isinstance(publisher._publishers[0], SamplePublisher1))

    def test_assemble_alert_publisher_for_output_dict_key_array(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Dict with Key -> List"""
        self._alert.publishers = {
            'demisto': [
                ('tests.unit.stream_alert_alert_processor.test_publishers.test_core.'
                 'SamplePublisher1'),
                ('tests.unit.stream_alert_alert_processor.test_publishers.test_core.'
                 'SamplePublisher2'),
            ],
            'pagerduty': [
                'tests.unit.stream_alert_alert_processor.test_publishers.test_core.SamplePublisher3'
            ],
        }

        publisher = _assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 2)

    def test_assemble_alert_publisher_for_output_dict_key_descriptor_string(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Dict matches Desc String"""
        self._alert.publishers = {
            'demisto:some_descriptor': ('tests.unit.stream_alert_alert_processor.test_publishers.'
                                        'test_core.SamplePublisher1'),
            'pagerduty': [
                'tests.unit.stream_alert_alert_processor.test_publishers.test_core.SamplePublisher2'
            ],
        }

        publisher = _assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 1)

    def test_assemble_alert_publisher_for_output_dict_key_descriptor_list(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Dict matches Desc List"""
        self._alert.publishers = {
            'demisto:some_descriptor': [
                ('tests.unit.stream_alert_alert_processor.test_publishers.test_core.'
                 'SamplePublisher1'),
                ('tests.unit.stream_alert_alert_processor.test_publishers.test_core.'
                 'SamplePublisher2'),
            ],
            'pagerduty': [
                'tests.unit.stream_alert_alert_processor.test_publishers.test_core.SamplePublisher3'
            ]
        }

        publisher = _assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 2)

    def test_assemble_alert_publisher_for_output_dict_key_both_descriptor_output_list(self):
        """AlertPublisher - AlertPublisherRepository - assemble() - Dict full match Lists"""
        self._alert.publishers = {
            'demisto': [
                ('tests.unit.stream_alert_alert_processor.test_publishers.test_core.'
                 'SamplePublisher1'),
                ('tests.unit.stream_alert_alert_processor.test_publishers.test_core.'
                 'SamplePublisher2'),
            ],
            'demisto:some_descriptor': [
                ('tests.unit.stream_alert_alert_processor.test_publishers.test_core.'
                 'SamplePublisher3'),
                ('tests.unit.stream_alert_alert_processor.test_publishers.test_core.'
                 'sample_publisher_4'),
            ],
            'pagerduty': [
                ('tests.unit.stream_alert_alert_processor.test_publishers.test_core.'
                 'sample_publisher_5')
            ]
        }

        publisher = _assemble_alert_publisher_for_output(
            self._alert,
            self._output,
            self._descriptor
        )

        assert_true(isinstance(publisher, CompositePublisher))
        assert_equal(len(publisher._publishers), 4)

        # Order is important
        assert_true(isinstance(publisher._publishers[0], SamplePublisher3))
        assert_true(isinstance(publisher._publishers[1], WrappedFunctionPublisher))
        assert_true(isinstance(publisher._publishers[2], SamplePublisher1))
        assert_true(isinstance(publisher._publishers[3], SamplePublisher2))


class TestCompositePublisher(object):

    @staticmethod
    def test_composite_publisher_ordering():
        """CompositePublisher - Ensure publishers executed in correct order"""
        publisher = CompositePublisher([
            SamplePublisher1(),
            WrappedFunctionPublisher(sample_publisher_blank),
            SamplePublisher2(),
        ])

        alert = get_alert()
        publication = publisher.publish(alert, {})

        expectation = {'test2': True}
        assert_equal(publication, expectation)

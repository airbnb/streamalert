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
from nose.tools import assert_equal, assert_true, assert_false

from stream_alert.alert_processor.helpers import compose_alert
from stream_alert.alert_processor.outputs.output_base import OutputDispatcher
from tests.unit.stream_alert_alert_processor.helpers import get_alert


def test_shorten_title():
    """Publishers - PagerDuty - ShortenTitle"""
    alert = get_alert(context={'context': 'value'})
    alert.created = datetime(2019, 1, 1)
    alert.publishers = {
        'pagerduty': 'publishers.community.pagerduty.pagerduty_layout.ShortenTitle',
    }
    output = MagicMock(spec=OutputDispatcher)
    output.__service__ = 'pagerduty'
    descriptor = 'unit_test_channel'

    publication = compose_alert(alert, output, descriptor)

    expectation = {
        '@pagerduty.description': 'cb_binarystore_file_added',
        '@pagerduty-v2.summary': 'cb_binarystore_file_added',
        '@pagerduty-incident.incident_title': 'cb_binarystore_file_added'
    }
    assert_equal(publication, expectation)


def test_as_custom_details_default():
    """Publishers - PagerDuty - as_custom_details - Default"""
    alert = get_alert(context={'context': 'value'})
    alert.created = datetime(2019, 1, 1)
    alert.publishers = {
        'pagerduty': [
            'stream_alert.shared.publisher.DefaultPublisher',
            'publishers.community.pagerduty.pagerduty_layout.as_custom_fields'
        ]
    }
    output = MagicMock(spec=OutputDispatcher)
    output.__service__ = 'pagerduty'
    descriptor = 'unit_test_channel'

    publication = compose_alert(alert, output, descriptor)

    expectation = {
        'publishers': {
            'pagerduty': [
                'stream_alert.shared.publisher.DefaultPublisher',
                'publishers.community.pagerduty.pagerduty_layout.as_custom_fields'
            ]
        },
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
            'compressed_size': '9982', 'node_id': '1', 'cb_server': 'cbserver',
            'timestamp': '1496947381.18', 'md5': '0F9AA55DA3BDE84B35656AD8911A22E1',
            'type': 'binarystore.file.added',
            'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
            'size': '21504'
        },
        'context': {'context': 'value'}, 'staged': False
    }
    assert_equal(publication, expectation)


def test_as_custom_details_ignores_custom_fields():
    """Publishers - PagerDuty - as_custom_details - Ignore Magic Keys"""
    alert = get_alert(context={'context': 'value'})
    alert.created = datetime(2019, 1, 1)
    alert.publishers = {
        'pagerduty': [
            'stream_alert.shared.publisher.DefaultPublisher',
            'publishers.community.pagerduty.pagerduty_layout.ShortenTitle',
            'publishers.community.pagerduty.pagerduty_layout.as_custom_details',
        ]
    }
    output = MagicMock(spec=OutputDispatcher)
    output.__service__ = 'pagerduty'
    descriptor = 'unit_test_channel'

    publication = compose_alert(alert, output, descriptor)

    # We don't care about the entire payload; let's check a few top-level keys we know
    # are supposed to be here..
    assert_true(publication['source_entity'])
    assert_true(publication['outputs'])
    assert_true(publication['log_source'])

    # Check that the title keys exists
    assert_true(publication['@pagerduty.description'])

    # now check that the details key exists
    assert_true(publication['@pagerduty.details'])

    # And check that it has no magic keys
    assert_false('@pagerduty.description' in publication['@pagerduty.details'])
    assert_false('@pagerduty-v2.summary' in publication['@pagerduty.details'])


def test_v2_high_urgency():
    """Publishers - PagerDuty - v2_high_urgency"""
    alert = get_alert(context={'context': 'value'})
    alert.created = datetime(2019, 1, 1)
    alert.publishers = {
        'pagerduty': [
            'publishers.community.pagerduty.pagerduty_layout.v2_high_urgency'
        ]
    }
    output = MagicMock(spec=OutputDispatcher)
    output.__service__ = 'pagerduty'
    descriptor = 'unit_test_channel'

    publication = compose_alert(alert, output, descriptor)

    expectation = {'@pagerduty-incident.urgency': 'high', '@pagerduty-v2.severity': 'critical'}
    assert_equal(publication, expectation)


def test_v2_low_urgency():
    """Publishers - PagerDuty - v2_low_urgency"""
    alert = get_alert(context={'context': 'value'})
    alert.created = datetime(2019, 1, 1)
    alert.publishers = {
        'pagerduty': [
            'publishers.community.pagerduty.pagerduty_layout.v2_low_urgency'
        ]
    }
    output = MagicMock(spec=OutputDispatcher)
    output.__service__ = 'pagerduty'
    descriptor = 'unit_test_channel'

    publication = compose_alert(alert, output, descriptor)

    expectation = {'@pagerduty-incident.urgency': 'low', '@pagerduty-v2.severity': 'warning'}
    assert_equal(publication, expectation)


def test_pretty_print_arrays():
    """Publishers - PagerDuty - PrettyPrintArrays"""
    alert = get_alert(context={'populate_fields': ['publishers', 'cb_server', 'staged']})
    alert.created = datetime(2019, 1, 1)
    alert.publishers = {
        'pagerduty': [
            'stream_alert.shared.publisher.DefaultPublisher',
            'publishers.community.generic.populate_fields',
            'publishers.community.pagerduty.pagerduty_layout.PrettyPrintArrays'
        ]
    }
    output = MagicMock(spec=OutputDispatcher)
    output.__service__ = 'pagerduty'
    descriptor = 'unit_test_channel'

    publication = compose_alert(alert, output, descriptor)

    expectation = {
        'publishers': [
            {
                'pagerduty': (
                    'stream_alert.shared.publisher.DefaultPublisher\n\n----------\n\n'
                    'publishers.community.generic.populate_fields\n\n----------\n\n'
                    'publishers.community.pagerduty.pagerduty_layout.PrettyPrintArrays'
                )
            }
        ],
        'staged': 'False',
        'cb_server': 'cbserver'
    }
    assert_equal(publication, expectation)


def test_attach_image():
    """Publishers - PagerDuty - AttachImage"""
    alert = get_alert()
    alert.created = datetime(2019, 1, 1)
    alert.publishers = {
        'pagerduty': [
            'publishers.community.pagerduty.pagerduty_layout.AttachImage'
        ]
    }

    output = MagicMock(spec=OutputDispatcher)
    output.__service__ = 'pagerduty'
    descriptor = 'unit_test_channel'

    publication = compose_alert(alert, output, descriptor)

    expectation = {
        '@pagerduty-v2.images': [
            {
                'src': 'https://streamalert.io/en/stable/_images/sa-banner.png',
                'alt': 'StreamAlert Docs',
                'href': 'https://streamalert.io/en/stable/'
            }
        ],
        '@pagerduty.contexts': [
            {
                'src': 'https://streamalert.io/en/stable/_images/sa-banner.png',
                'type': 'image'
            }
        ]
    }
    assert_equal(publication, expectation)

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
from nose.tools import assert_equal, assert_less_equal

from publishers.community.slack.slack_layout import (
    AttachFullRecord,
    AttachPublication,
    AttachRuleInfo,
    AttachStringTemplate,
    Summary
)
from tests.unit.stream_alert_alert_processor.helpers import get_alert


class TestSummary(object):

    def setup(self):
        self._publisher = Summary()

    def test_simple(self):
        """Publishers - Slack - Summary"""
        alert = get_alert()

        alert.created = datetime.utcfromtimestamp(1546329600)

        publication = self._publisher.publish(alert, {})

        expectation = {
            '@slack.text': 'Rule triggered',
            '@slack._previous_publication': {},
            '@slack.attachments': [
                {
                    'author_link': '',
                    'color': '#ff5a5f',
                    'text': 'Info about this rule and what actions to take',
                    'author_name': '',
                    'mrkdwn_in': [],
                    'thumb_url': '',
                    'title': 'cb_binarystore_file_added',
                    'footer': '',
                    'ts': 1546329600,
                    'title_link': (
                        'https://github.com/airbnb/streamalert/search'
                        '?q=cb_binarystore_file_added+path%3A%2Frules'
                    ),
                    'image_url': '',
                    'fallback': 'Rule triggered: cb_binarystore_file_added',
                    'author_icon': '',
                    'footer_icon': '',
                }
            ]
        }

        assert_equal(publication['@slack.text'], expectation['@slack.text'])
        assert_equal(
            publication['@slack._previous_publication'],
            expectation['@slack._previous_publication']
        )
        assert_equal(len(publication['@slack.attachments']), len(expectation['@slack.attachments']))
        assert_equal(
            publication['@slack.attachments'][0].keys(),
            expectation['@slack.attachments'][0].keys()
        )
        assert_equal(publication['@slack.attachments'][0], expectation['@slack.attachments'][0])


class TestAttachRuleInfo(object):

    def setup(self):
        self._publisher = AttachRuleInfo()

    def test_simple(self):
        """Publishers - Slack - AttachRuleInfo"""
        alert = get_alert()
        alert.created = datetime(2019, 1, 1)
        alert.rule_description = '''
Author: unit_test
Reference: somewhere_over_the_rainbow
Description: ?
Att&ck vector:  Assuming direct control
'''

        publication = self._publisher.publish(alert, {})

        expectation = {
            '@slack.attachments': [
                {
                    'color': '#8ce071',
                    'fields': [
                        {
                            'title': 'Att&ck vector',
                            'value': 'Assuming direct control',
                        },
                        {
                            'title': 'Reference',
                            'value': 'somewhere_over_the_rainbow',
                        }
                    ]
                }
            ]
        }

        assert_equal(publication, expectation)


class TestAttachPublication(object):

    def setup(self):
        self._publisher = AttachPublication()

    def test_simple(self):
        """Publishers - Slack - AttachPublication"""
        alert = get_alert()
        alert.created = datetime(2019, 1, 1)

        previous = {
            '@slack._previous_publication': {'foo': 'bar'},
            '@slack.attachments': [
                {
                    'text': 'attachment1',
                },
            ]
        }
        publication = self._publisher.publish(alert, previous)

        expectation = {
            '@slack._previous_publication': {'foo': 'bar'},
            '@slack.attachments': [
                {'text': 'attachment1'},
                {
                    'color': '#00d1c1',
                    'text': '```\n{\n  "foo": "bar"\n}\n```',
                    'mrkdwn_in': ['text'],
                    'title': 'Alert Data:'
                }
            ]
        }

        assert_equal(publication, expectation)


class TestAttachStringTemplate(object):
    def setup(self):
        self._publisher = AttachStringTemplate()

    def test_from_publication(self):
        """Publishers - Slack - AttachStringTemplate - from publication"""
        alert = get_alert(context={
            'slack_message_template': 'Foo {bar} baz {buzz}'
        })
        alert.created = datetime(2019, 1, 1)

        publication = self._publisher.publish(alert, {'bar': 'BAR?', 'buzz': 'BUZZ?'})

        expectation = {
            '@slack.attachments': [
                {'color': '#ffb400', 'text': 'Foo BAR? baz BUZZ?'}
            ],
            'bar': 'BAR?',
            'buzz': 'BUZZ?',
        }
        assert_equal(publication, expectation)

    def test_from_previous_publication(self):
        """Publishers - Slack - AttachStringTemplate - from previous publication"""
        alert = get_alert(context={
            'slack_message_template': 'Foo {bar} baz {buzz}'
        })
        alert.created = datetime(2019, 1, 1)

        publication = self._publisher.publish(alert, {
            '@slack._previous_publication': {
                'bar': 'BAR?', 'buzz': 'BUZZ?',
            },
            'bar': 'wrong',
            'buzz': 'wrong',
        })

        expectation = {
            '@slack._previous_publication': {'bar': 'BAR?', 'buzz': 'BUZZ?'},
            '@slack.attachments': [{'color': '#ffb400', 'text': 'Foo BAR? baz BUZZ?'}],
            'bar': 'wrong',
            'buzz': 'wrong',
        }
        assert_equal(publication, expectation)


class TestAttachFullRecord(object):

    def setup(self):
        self._publisher = AttachFullRecord()

    def test_simple(self):
        """Publishers - Slack - AttachFullRecord"""
        alert = get_alert()
        alert.created = datetime(2019, 1, 1)

        publication = self._publisher.publish(alert, {})

        expectation = {
            '@slack.attachments': [
                {
                    'footer': 'via <https://console.aws.amazon.com/s3/home|s3>',
                    'fields': [
                        {'value': '79192344-4a6d-4850-8d06-9c3fef1060a4', 'title': 'Alert Id'}
                    ],
                    'mrkdwn_in': ['text'],
                    'author': 'corp-prefix.prod.cb.region',
                    'color': '#7b0051',
                    'text': (
                        '```\n\n{\n  "cb_server": "cbserver",\n  "compressed_size": "9982",'
                        '\n  "file_path": "/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip",'
                        '\n  "md5": "0F9AA55DA3BDE84B35656AD8911A22E1",\n  "node_id": "1",'
                        '\n  "size": "21504",\n  "timestamp": "1496947381.18",'
                        '\n  "type": "binarystore.file.added"\n}\n```'
                    ),
                    'title': 'Record',
                    'footer_icon': ''
                }
            ]
        }
        assert_equal(publication, expectation)

    def test_record_splitting(self):
        """Publishers - Slack - AttachFullRecord - Split Record"""
        alert = get_alert()
        alert.created = datetime(2019, 1, 1)

        alert.record = {
            'massive_record': []
        }
        for index in range(0, 999):
            alert.record['massive_record'].append({
                'index': index,
                'value': 'foo'
            })

        publication = self._publisher.publish(alert, {})

        attachments = publication['@slack.attachments']

        assert_equal(len(attachments), 14)
        for attachment in attachments:
            assert_less_equal(len(attachment['text']), 4000)

        assert_equal(attachments[0]['title'], 'Record')
        assert_equal(len(attachments[0]['fields']), 0)
        assert_equal(attachments[0]['footer'], '')

        assert_equal(attachments[1]['title'], '')
        assert_equal(len(attachments[1]['fields']), 0)
        assert_equal(attachments[1]['footer'], '')

        assert_equal(attachments[13]['title'], '')
        assert_equal(len(attachments[13]['fields']), 1)
        assert_equal(attachments[13]['footer'], 'via <https://console.aws.amazon.com/s3/home|s3>')

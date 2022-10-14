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
import calendar
import json
import urllib.error
import urllib.parse
import urllib.request
from html import escape as html_escape

from streamalert.shared.description import RuleDescriptionParser
from streamalert.shared.publisher import AlertPublisher, Register

RAUSCH = '#ff5a5f'
BABU = '#00d1c1'
LIMA = '#8ce071'
HACKBERRY = '#7b0051'
BEACH = '#ffb400'


@Register
class Summary(AlertPublisher):
    """Adds a brief summary with the rule triggered, author, description, and time

    To customize the behavior of this Publisher, it is recommended to subclass this and override
    parameters as necessary. For example, an implementation could override _GITHUB_REPO_URL with
    the URL appropriate for the organization using StreamAlert.
    """

    _GITHUB_REPO_URL = 'https://github.com/airbnb/streamalert'
    _SEARCH_PATH = '/search'
    _RULES_PATH = '/rules'

    def publish(self, alert, publication):
        rule_name = alert.rule_name
        rule_description = alert.rule_description
        rule_presentation = RuleDescriptionParser.present(rule_description)

        author = rule_presentation['author']

        return {
            '@slack.text':
            'Rule triggered',
            '@slack.attachments': [{
                'fallback':
                f'Rule triggered: {rule_name}',
                'color':
                self._color(),
                'author_name':
                author,
                'author_link':
                self._author_url(author),
                'author_icon':
                self._author_icon(author),
                'title':
                rule_name,
                'title_link':
                self._title_url(rule_name),
                'text':
                html_escape(rule_presentation['description'], quote=False),
                'image_url':
                '',
                'thumb_url':
                '',
                'footer':
                '',
                'footer_icon':
                '',
                'ts':
                calendar.timegm(alert.created.timetuple()) if alert.created else '',
                'mrkdwn_in': []
            }],
            '@slack._previous_publication':
            publication
        }

    @staticmethod
    def _color():
        """The color of this section"""
        return RAUSCH

    @classmethod
    def _author_url(cls, _):
        """When given an author name, returns a clickable link, if any"""
        return ''

    @classmethod
    def _author_icon(cls, _):
        """When given an author name, returns a URL to an icon, if any"""
        return ''

    @classmethod
    def _title_url(cls, rule_name):
        """When given the rule_name, returns a clickable link, if any"""

        # It's actually super hard to generate a exact link to a file just from the rule_name,
        # because the rule/ directory files are not deployed with the publishers in the alert
        # processor.
        # Instead, we send them to Github with a formatted query string that is LIKELY to
        # find the correct file.
        #
        # If you do not want URLs to show up, simply override this method and return empty string.
        return '{}{}?{}'.format(
            cls._GITHUB_REPO_URL, cls._SEARCH_PATH,
            urllib.parse.urlencode({'q': f'{rule_name} path:{cls._RULES_PATH}'}))


@Register
class AttachRuleInfo(AlertPublisher):
    """This publisher adds a slack attachment with fields from the rule's description

    It can include such fields as "reference" or "playbook" but will NOT include the description
    or the author.
    """
    def publish(self, alert, publication):
        publication['@slack.attachments'] = publication.get('@slack.attachments', [])

        rule_description = alert.rule_description
        rule_presentation = RuleDescriptionParser.present(rule_description)

        publication['@slack.attachments'].append({
            'color':
            self._color(),
            'fields': [{
                'title': key.capitalize(),
                'value': rule_presentation['fields'][key]
            } for key in rule_presentation['fields'].keys()],
        })

        return publication

    @staticmethod
    def _color():
        return LIMA


@Register
class AttachPublication(AlertPublisher):
    """A publisher that attaches previous publications as an attachment

    By default, this publisher needs to be run after the Summary publisher, as it depends on
    the magic-magic _previous_publication field.
    """
    def publish(self, alert, publication):
        if '@slack._previous_publication' not in publication or '@slack.attachments' not in publication:
            # This publisher cannot be run except immediately after the Summary publisher
            return publication

        publication_block = '```\n{}\n```'.format(
            json.dumps(self._get_publication(alert, publication),
                       indent=2,
                       sort_keys=True,
                       separators=(',', ': ')))

        publication['@slack.attachments'].append({
            'color': self._color(),
            'title': 'Alert Data:',
            'text': html_escape(publication_block, quote=False),
            'mrkdwn_in': ['text'],
        })

        return publication

    @staticmethod
    def _color():
        return BABU

    @staticmethod
    def _get_publication(_, publication):
        return publication['@slack._previous_publication']


@Register
class AttachStringTemplate(AlertPublisher):
    """An extremely flexible publisher that simply renders an attachment as text

    By default, this publisher accepts a template from the alert.context['slack_message_template']
    which is .format()'d with the current publication. This allows individual rules to render
    whatever they want. The template is a normal slack message, so it can support newline
    characters, and any of slack's pseudo-markdown.

    Subclass implementations of this can decide to override any of the implementation or come
    up with their own!

    If this publisher is run after the Summary publisher, it will correctly pull the original
    publication from the @slack._previous_publication, otherwise it uses the default publication.
    """
    def publish(self, alert, publication):
        rendered_text = self._render_text(alert, publication)

        publication['@slack.attachments'] = publication.get('@slack.attachments', [])
        publication['@slack.attachments'].append({
            'color': self._color(),
            'text': html_escape(rendered_text,quote=False),
        })

        return publication

    @classmethod
    def _render_text(cls, alert, publication):
        template = cls._get_format_template(alert, publication)
        args = cls._get_template_args(alert, publication)

        return template.format(**args)

    @staticmethod
    def _get_format_template(alert, _):
        return alert.context.get('slack_message_template', '[MISSING TEMPLATE]')

    @staticmethod
    def _get_template_args(_, publication):
        return (publication['@slack._previous_publication']
                if '@slack._previous_publication' in publication else publication)

    @staticmethod
    def _color():
        return BEACH


@Register
class AttachFullRecord(AlertPublisher):
    """This publisher attaches slack attachments generated from the Alert's full record

    The full record is likely to be significantly longer than the slack max messages size.
    So we cut up the record by rows and send it as a series of 1 or more attachments.
    The attachments are rendered in slack in a way such that a mouse drag and copy will
    copy the entire JSON in-tact.

    The first attachment is slightly different as it includes the source entity where the
    record originated from. The last attachment includes a footer.
    """
    _SLACK_MAXIMUM_ATTACHMENT_CHARACTER_LENGTH = 4000

    # Reserve space at the beginning and end of the attachment text for backticks and newlines
    _LENGTH_PADDING = 10

    def publish(self, alert, publication):
        publication['@slack.attachments'] = publication.get('@slack.attachments', [])

        # Generate the record and then dice it up into parts
        record_document = json.dumps(alert.record, indent=2, sort_keys=True, separators=(',', ': '))

        # Escape the document FIRST because it can increase character length which can throw off
        # document slicing
        record_document = html_escape(record_document, quote=False)
        record_document_lines = record_document.split('\n')

        def make_attachment(document, is_first, is_last):

            footer = ''
            if is_last:
                footer_url = self._source_service_url(alert.source_service)
                if footer_url:
                    footer = f'via <{footer_url}|{alert.source_service}>'
                else:
                    f'via {alert.source_service}'

            return {
                'color': self._color(),
                'author': alert.source_entity if is_first else '',
                'title': 'Record' if is_first else '',
                'text': f'```\n{document}\n```',
                'fields': [{
                    "title": "Alert Id",
                    "value": alert.alert_id,
                }] if is_last else [],
                'footer': footer,
                'footer_icon': self._footer_icon_from_service(alert.source_service),
                'mrkdwn_in': ['text'],
            }

        character_limit = self._SLACK_MAXIMUM_ATTACHMENT_CHARACTER_LENGTH - self._LENGTH_PADDING
        is_first_document = True
        next_document = ''
        while len(record_document_lines) > 0:
            # Loop, removing one line at a time and attempting to attach it to the next document
            # When the next document nears the maximum attachment size, it is flushed, generating
            # a new attachment, and the document is reset before the loop pops off the next line.

            next_item_length = len(record_document_lines[0])
            next_length = next_item_length + len(next_document)
            if next_document and next_length > character_limit:
                # Do not pop off the item just yet.
                publication['@slack.attachments'].append(
                    make_attachment(next_document, is_first_document, False))
                next_document = ''
                is_first_document = False

            next_document += '\n' + record_document_lines.pop(0)

        # Attach last document, if any remains
        if next_document:
            publication['@slack.attachments'].append(
                make_attachment(next_document, is_first_document, True))

        return publication

    @staticmethod
    def _color():
        return HACKBERRY

    @staticmethod
    def _source_service_url(source_service):
        """A best-effort guess at the AWS dashboard link for the requested service."""
        return f'https://console.aws.amazon.com/{source_service}/home'

    @staticmethod
    def _footer_icon_from_service(_):
        """Returns the URL of an icon, given an AWS service"""
        return ''

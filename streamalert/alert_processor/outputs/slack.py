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
import html
from collections import OrderedDict

from streamalert.alert_processor.helpers import (compose_alert,
                                                 elide_string_middle)
from streamalert.alert_processor.outputs.output_base import (
    OutputDispatcher, OutputProperty, OutputRequestFailure, StreamAlertOutput)
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


@StreamAlertOutput
class SlackOutput(OutputDispatcher):
    """SlackOutput handles all alert dispatching for Slack"""
    __service__ = 'slack'
    # Slack recommends no messages larger than 4000 bytes. This does not account for unicode
    MAX_MESSAGE_SIZE = 4000
    MAX_ATTACHMENTS = 20

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be assigned by the user when configuring a new Slack
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Slack also requires a user provided 'webhook' url that is comprised of the slack api url
        and the unique integration key for this output. This value should be should be masked
        during input and is a credential requirement.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this Slack integration '
                            '(ie: channel, group, etc)')),
            ('url',
             OutputProperty(description='the full Slack webhook url, including the secret',
                            mask_input=True,
                            input_restrictions={' '},
                            cred_requirement=True))
        ])

    @classmethod
    def _split_attachment_text(cls, alert_record):
        """Yield messages that should be sent to slack.

        Args:
            alert_record (dict): Dictionary representation of the alert
                relevant to the triggered rule

        Yields:
            str: Properly split messages to be sent as attachments to slack
        """
        # Convert the alert we have to a nicely formatted string for slack
        alert_text = '\n'.join(cls._json_to_slack_mrkdwn(alert_record, 0))

        # Slack requires escaping the characters: '&', '>' and '<' and html does just that
        alert_text = html.escape(alert_text)

        while alert_text:
            if len(alert_text) <= cls.MAX_MESSAGE_SIZE:
                yield alert_text
                break

            # Find the closest line break prior to this index
            index = alert_text[:cls.MAX_MESSAGE_SIZE + 1].rfind('\n')

            # If a new line was not found, split on the closest space instead
            if index == -1:
                index = alert_text[:cls.MAX_MESSAGE_SIZE + 1].rfind(' ')

            # If there is no good place to split the message, just use the max index
            if index == -1:
                index = cls.MAX_MESSAGE_SIZE

            # Append the message part up until this index, and move to the next chunk
            yield alert_text[:index]
            alert_text = alert_text[index + 1:]

    @classmethod
    def _format_default_attachments(cls, alert, alert_publication, fallback_text):
        """Format the message to be sent to slack.

        Args:
            alert (Alert): The alert
            alert_publication (dict): Alert relevant to the triggered rule
            fallback_text (str): A formatted rule header to be included with each
                attachment as fallback text (to be shown on mobile, etc)

        Returns:
            list(dict): A list of dictionaries with the formatted attachment to be sent to Slack
                as the text
        """
        record = alert.record
        rule_description = alert.rule_description

        messages = list(cls._split_attachment_text(record))

        attachments = []
        for index, message in enumerate(messages, start=1):
            title = 'Record:'
            if len(messages) > 1:
                title = f'Record (Part {index} of {len(messages)}):'
            rule_desc = ''
            # Only print the rule description on the first attachment
            if index == 1:
                rule_desc = rule_description
                rule_desc = f'*Rule Description:*\n{rule_desc}\n'

            # https://api.slack.com/docs/message-attachments#attachment_structure
            attachments.append({
                'fallback': fallback_text,
                'color': '#b22222',
                'pretext': rule_desc,
                'title': title,
                'text': message,
                'mrkdwn_in': ['text', 'pretext']
            })

            if index == cls.MAX_ATTACHMENTS:
                LOGGER.warning('%s: %d-part message truncated to %d parts', alert_publication,
                               len(messages), cls.MAX_ATTACHMENTS)
                break

        return attachments

    @classmethod
    def _get_attachment_skeleton(cls):
        """Returns a skeleton for a Slack attachment containing various default values.

        Return:
             dict
        """
        return {
            # String
            # Plaintext summary of the attachment; renders in non-markdown compliant clients,
            # such as push notifications.
            'fallback': '',

            # String, hex color
            # Colors the vertical bar to the left of the text.
            'color': '#36a64f',

            # String
            # Text that appears above the vertical bar to the left of the attachment.
            # Supports markdown if it's included in "mrkdwn_in"
            'pretext': '',

            # String
            # The attachment's author name.
            # If this field is omitted, then the entire author row is omitted.
            'author_name': '',

            # String, URL
            # Provide a URL; Adds a clickable link to the author name
            'author_link': '',

            # String, URL of an image
            # The icon appears to the left of the author name
            'author_icon': '',

            # String
            # Appears as bold text above the attachment itself.
            # If this field is omitted, the entire title row is omitted.
            'title': '',

            # String, URL
            # Adds a clickable link to the title
            'title_link': '',

            # String
            # Raw text that appears in the attachment, below the title but above the fields
            # Supports markdown if it's included in "mrkdwn_in".
            # Use \n for newline characters.
            # This field has a field limit of cls.MAX_MESSAGE_SIZE
            'text': '',

            # Array of dicts; Each dict should have keys "title", "value", "short"
            # An array of fields that appears below the text. These fields are clearly delineated
            # with title and value.
            'fields': [
                # Sample field:
                # {
                #     "title": "Priority",
                #     "value": "High",
                #     "short": False
                # }
            ],

            # String, URL of an image
            # Large image that appears as an attachment
            'image_url': '',

            # String, URL of an image
            # When image_url is omitted, this one renders a smaller image to the right
            'thumb_url': '',

            # String
            # Appears at the very bottom
            # If this field is omitted, also omits the footer icon
            'footer': '',

            # String, URL
            # This icon appears to the left of the footer
            'footer_icon': '',

            # Integer, Unix timestamp
            # This will show up next to the footer at the bottom.
            # This timestamp does not change the time the message is actually sent.
            'ts': '',

            # List of strings
            # Defines which of the above fields will support Slack's simple markdown (with special
            # characters like *, ~, _, `, or ```... etc)
            # By default, we respect markdown in "text" and "pretext"
            "mrkdwn_in": [
                'text',
                'pretext',
            ],
        }

    @classmethod
    def _standardize_custom_attachments(cls, custom_slack_attachments):
        """Supplies default fields to given attachments and validates their structure.

        You can test out custom attachments using this tool:
          https://api.slack.com/docs/messages/builder

        When publishers provider custom slack attachments to the SlackOutput, it offers increased
        flexibility, but requires more work. Publishers need to pay attention to the following:

        - Slack requires escaping the characters: '&', '>' and '<'
        - Slack messages have a limit of 4000 characters
        - Individual slack messages support a maximum of 20 attachments


        Args:
            custom_slack_attachments (list): A list of dicts that is provided by the publisher.

        Returns:
            list: The value to the "attachments" Slack API argument
        """

        attachments = []

        for custom_slack_attachment in custom_slack_attachments:
            attachment = cls._get_attachment_skeleton()
            attachment.update(custom_slack_attachment)

            # Enforce maximum text length; make sure to check size AFTER escaping in case
            # extra escape characters pushes it over the limit
            if len(attachment['text']) > cls.MAX_MESSAGE_SIZE:
                LOGGER.warning('Custom attachment was truncated to length %d. Full message: %s',
                               cls.MAX_MESSAGE_SIZE, attachment['text'])
                attachment['text'] = elide_string_middle(attachment['text'], cls.MAX_MESSAGE_SIZE)

            attachments.append(attachment)

            # Enforce maximum number of attachments
            if len(attachments) >= cls.MAX_ATTACHMENTS:
                LOGGER.warning('Message with %d custom attachments was truncated to %d attachments',
                               len(custom_slack_attachments), cls.MAX_ATTACHMENTS)
                break

        return attachments

    @classmethod
    def _format_message(cls, alert, alert_publication):
        """Format the message to be sent to slack.

        Args:
            alert (Alert): The alert
            alert_publication (dict): Alert relevant to the triggered rule

        Returns:
            dict: message with attachments to send to Slack.
                The message will look like:
                    StreamAlert Rule Triggered: rule_name
                    Rule Description:
                    This will be the docstring from the rule, sent as the rule_description

                    Record (Part 1 of 2):
                    ...
        """
        default_header_text = f'*StreamAlert Rule Triggered: {alert.rule_name}*'
        header_text = alert_publication.get('@slack.text', default_header_text)

        if '@slack.attachments' in alert_publication:
            attachments = cls._standardize_custom_attachments(
                alert_publication.get('@slack.attachments'))
        else:
            # Default attachments
            attachments = cls._format_default_attachments(alert, alert_publication, header_text)

        # Return the json dict payload to be sent to slack
        return {'text': header_text, 'mrkdwn': True, 'attachments': attachments}

    @classmethod
    def _json_to_slack_mrkdwn(cls, json_values, indent_count):
        """Translate a json object into a more human-readable list of lines
        This will handle recursion of all nested maps and lists within the object

        Args:
            json_values: variant to be translated (could be json map, list, etc)
            indent_count (int): Number of tabs to prefix each line with

        Returns:
            list: strings that have been properly tabbed and formatted for printing
        """
        tab = '\t'
        all_lines = []
        if isinstance(json_values, dict):
            all_lines = cls._json_map_to_text(json_values, tab, indent_count)
        elif isinstance(json_values, list):
            all_lines = cls._json_list_to_text(json_values, tab, indent_count)
        else:
            all_lines.append(f'{json_values}')

        return all_lines

    @classmethod
    def _json_map_to_text(cls, json_values, tab, indent_count):
        """Translate a map from json (dict) into a more human-readable list of lines
        This will handle recursion of all nested maps and lists within the map

        Args:
            json_values (dict): dictionary to be iterated over and formatted
            tab (str): string value to use for indentation
            indent_count (int): Number of tabs to prefix each line with

        Returns:
            list: strings that have been properly tabbed and formatted for printing
        """
        all_lines = []
        for key, value in sorted(json_values.items()):
            if isinstance(value, (dict, list)) and value:
                all_lines.append(f'{tab * indent_count}*{key}:*')
                all_lines.extend(cls._json_to_slack_mrkdwn(value, indent_count + 1))
            else:
                new_lines = cls._json_to_slack_mrkdwn(value, indent_count + 1)
                if len(new_lines) == 1:
                    all_lines.append(f'{tab * indent_count}*{key}:* {new_lines[0]}')
                elif new_lines:
                    all_lines.append(f'{tab * indent_count}*{key}:*')
                    all_lines.extend(new_lines)
                else:
                    all_lines.append(f'{tab * indent_count}*{key}:* {value}')

        return all_lines

    @classmethod
    def _json_list_to_text(cls, json_values, tab, indent_count):
        """Translate a list from json into a more human-readable list of lines
        This will handle recursion of all nested maps and lists within the list

        Args:
            json_values (list): list to be iterated over and formatted
            tab (str): string value to use for indentation
            indent_count (int): Number of tabs to prefix each line with

        Returns:
            list: strings that have been properly tabbed and formatted for printing
        """
        all_lines = []
        for index, value in enumerate(json_values):
            if isinstance(value, (dict, list)) and value:
                all_lines.append(f'{tab * indent_count}*[{index + 1}]*')
                all_lines.extend(cls._json_to_slack_mrkdwn(value, indent_count + 1))
            else:
                new_lines = cls._json_to_slack_mrkdwn(value, indent_count + 1)
                if len(new_lines) == 1:
                    all_lines.append(f'{tab * indent_count}*[{index + 1}]* {new_lines[0]}')
                elif new_lines:
                    all_lines.append(f'{tab * indent_count}*[{index + 1}]*')
                    all_lines.extend(new_lines)
                else:
                    all_lines.append(f'{tab * indent_count}*[{index + 1}]* {value}')

        return all_lines

    def _dispatch(self, alert, descriptor):
        """Send alert text to Slack

        Publishing:
            By default the slack output sends a slack message comprising some default intro text
            and a series of attachments containing:
            * alert description
            * alert record, chunked into pieces if it's too long

            To override this behavior use the following fields:

            - @slack.text (str):
                    Replaces the text that appears as the first line in the slack message.

            - @slack.attachments (list[dict]):
                    A list of individual slack attachments to include in the message. Each
                    element of this list is a dict that must adhere to the syntax of attachments
                    on Slack's API.

                    @see cls._standardize_custom_attachments() for some insight into how individual
                    attachments can be written.

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        publication = compose_alert(alert, self, descriptor)

        slack_message = self._format_message(alert, publication)

        try:
            self._post_request_retry(creds['url'], slack_message)
        except OutputRequestFailure:
            return False

        return True

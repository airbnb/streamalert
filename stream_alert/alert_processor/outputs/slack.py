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
import cgi
from collections import OrderedDict

from stream_alert.alert_processor.outputs.output_base import (
    OutputDispatcher,
    OutputProperty,
    OutputRequestFailure,
    StreamAlertOutput
)
from stream_alert.alert_processor.publishers import publish_alert
from stream_alert.shared.logger import get_logger


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
                            cred_requirement=True))
        ])

    @classmethod
    def _split_attachment_text(cls, alert_record):
        """Yield messages that should be sent to slack.

        Args:
            alert_record (dict): Dictionary represntation of the alert
                relevant to the triggered rule

        Yields:
            str: Properly split messages to be sent as attachemnts to slack
        """
        # Convert the alert we have to a nicely formatted string for slack
        alert_text = '\n'.join(cls._json_to_slack_mrkdwn(alert_record, 0))

        # Slack requires escaping the characters: '&', '>' and '<' and cgi does just that
        alert_text = cgi.escape(alert_text)

        while alert_text:
            if len(alert_text) <= cls.MAX_MESSAGE_SIZE:
                yield alert_text
                break

            # Find the closest line break prior to this index
            index = alert_text[:cls.MAX_MESSAGE_SIZE+1].rfind('\n')

            # If a new line was not found, split on the closest space instead
            if index == -1:
                index = alert_text[:cls.MAX_MESSAGE_SIZE+1].rfind(' ')

            # If there is no good place to split the message, just use the max index
            if index == -1:
                index = cls.MAX_MESSAGE_SIZE

            # Append the message part up until this index, and move to the next chunk
            yield alert_text[:index]
            alert_text = alert_text[index+1:]

    @classmethod
    def _format_attachments(cls, alert_publication, header_text):
        """Format the message to be sent to slack.

        Args:
            alert_publication (dict): Alert relevant to the triggered rule
            header_text (str): A formatted rule header to be included with each
                attachemnt as fallback text (to be shown on mobile, etc)

        Yields:
            dict: A dictionary with the formatted attachemnt to be sent to Slack
                as the text
        """
        record = alert_publication.get('record', {})
        rule_description = alert_publication.get('rule_description', '')

        messages = list(cls._split_attachment_text(record))

        for index, message in enumerate(messages, start=1):
            title = 'Record:'
            if len(messages) > 1:
                title = 'Record (Part {} of {}):'.format(index, len(messages))
            rule_desc = ''
            # Only print the rule description on the first attachment
            if index == 1:
                rule_desc = rule_description
                rule_desc = '*Rule Description:*\n{}\n'.format(rule_desc)

            # Yield this attachemnt to be sent with the list of attachments
            yield {
                'fallback': header_text,
                'color': '#b22222',
                'pretext': rule_desc,
                'title': title,
                'text': message,
                'mrkdwn_in': ['text', 'pretext']
            }

            if index == cls.MAX_ATTACHMENTS:
                LOGGER.warning('%s: %d-part message truncated to %d parts',
                               alert_publication, len(messages), cls.MAX_ATTACHMENTS)
                break

    @classmethod
    def _format_message(cls, rule_name, alert_publication):
        """Format the message to be sent to slack.

        Args:
            rule_name (str): The name of the rule that triggered the alert
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
        header_text = '*StreamAlert Rule Triggered: {}*'.format(rule_name)
        attachments = list(cls._format_attachments(alert_publication, header_text))
        full_message = {
            'text': header_text,
            'mrkdwn': True,
            'attachments': attachments
        }

        # Return the json dict payload to be sent to slack
        return full_message

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
            all_lines.append('{}'.format(json_values))

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
        for key, value in sorted(json_values.iteritems()):
            if isinstance(value, (dict, list)) and value:
                all_lines.append('{}*{}:*'.format(tab*indent_count, key))
                all_lines.extend(cls._json_to_slack_mrkdwn(value, indent_count+1))
            else:
                new_lines = cls._json_to_slack_mrkdwn(value, indent_count+1)
                if len(new_lines) == 1:
                    all_lines.append('{}*{}:* {}'.format(tab*indent_count, key, new_lines[0]))
                elif new_lines:
                    all_lines.append('{}*{}:*'.format(tab*indent_count, key))
                    all_lines.extend(new_lines)
                else:
                    all_lines.append('{}*{}:* {}'.format(tab*indent_count, key, value))

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
                all_lines.append('{}*[{}]*'.format(tab*indent_count, index+1))
                all_lines.extend(cls._json_to_slack_mrkdwn(value, indent_count+1))
            else:
                new_lines = cls._json_to_slack_mrkdwn(value, indent_count+1)
                if len(new_lines) == 1:
                    all_lines.append('{}*[{}]* {}'.format(tab*indent_count, index+1, new_lines[0]))
                elif new_lines:
                    all_lines.append('{}*[{}]*'.format(tab*indent_count, index+1))
                    all_lines.extend(new_lines)
                else:
                    all_lines.append('{}*[{}]* {}'.format(tab*indent_count, index+1, value))

        return all_lines

    def _dispatch(self, alert, descriptor):
        """Send alert text to Slack

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        publication = publish_alert(alert, self, descriptor)
        rule_name = publication.get('rule_name', '')

        slack_message = self._format_message(rule_name, publication)

        try:
            self._post_request_retry(creds['url'], slack_message)
        except OutputRequestFailure:
            return False

        return True

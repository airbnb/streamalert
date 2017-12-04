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


@StreamAlertOutput
class SlackOutput(OutputDispatcher):
    """SlackOutput handles all alert dispatching for Slack"""
    __service__ = 'slack'
    # Slack recommends no messages larger than 4000 bytes. This does not account for unicode
    MAX_MESSAGE_SIZE = 4000

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be asssigned by the user when configuring a new Slack
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
    def _format_message(cls, rule_name, alert):
        """Format the message to be sent to slack.

        Args:
            rule_name (str): The name of the rule that triggered the alert
            alert: Alert relevant to the triggered rule

        Returns:
            dict: message with attachments to send to Slack.
                The message will look like:
                    StreamAlert Rule Triggered: rule_name
                    Rule Description:
                    This will be the docstring from the rule, sent as the rule_description

                    Record (Part 1 of 2):
                    ...
        """
        # Convert the alert we have to a nicely formatted string for slack
        alert_text = '\n'.join(cls._json_to_slack_mrkdwn(alert['record'], 0))
        # Slack requires escaping the characters: '&', '>' and '<' and cgi does just that
        alert_text = cgi.escape(alert_text)
        messages = []
        index = cls.MAX_MESSAGE_SIZE
        while alert_text != '':
            if len(alert_text) <= index:
                messages.append(alert_text)
                break

            # Find the closest line break prior to this index
            while index > 1 and alert_text[index] != '\n':
                index -= 1

            # Append the message part up until this index, and move to the next chunk
            messages.append(alert_text[:index])
            alert_text = alert_text[index+1:]

            index = cls.MAX_MESSAGE_SIZE

        header_text = '*StreamAlert Rule Triggered: {}*'.format(rule_name)
        full_message = {
            'text': header_text,
            'mrkdwn': True,
            'attachments': []
        }

        for index, message in enumerate(messages):
            title = 'Record:'
            if len(messages) > 1:
                title = 'Record (Part {} of {}):'.format(index+1, len(messages))
            rule_desc = ''
            # Only print the rule description on the first attachment
            if index == 0:
                rule_desc = alert['rule_description']
                rule_desc = '*Rule Description:*\n{}\n'.format(rule_desc)

            # Add this attachemnt to the full message array of attachments
            full_message['attachments'].append({
                'fallback': header_text,
                'color': '#b22222',
                'pretext': rule_desc,
                'title': title,
                'text': message,
                'mrkdwn_in': ['text', 'pretext']
            })

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
        for key, value in json_values.iteritems():
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

    def dispatch(self, **kwargs):
        """Send alert text to Slack

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        if not creds:
            return self._log_status(False)

        slack_message = self._format_message(kwargs['rule_name'], kwargs['alert'])

        try:
            success = self._post_request_retry(creds['url'], slack_message)
        except OutputRequestFailure:
            success = False

        return self._log_status(success)

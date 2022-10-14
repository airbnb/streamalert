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
# pylint: disable=protected-access,attribute-defined-outside-init,no-self-use
from collections import Counter, OrderedDict
from unittest.mock import MagicMock, Mock, patch

from streamalert.alert_processor.helpers import compose_alert
from streamalert.alert_processor.outputs.slack import SlackOutput
from tests.unit.streamalert.alert_processor.helpers import (get_alert,
                                                            get_random_alert)


@patch('streamalert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
class TestSlackOutput:
    """Test class for SlackOutput"""
    DESCRIPTOR = 'unit_test_channel'
    SERVICE = 'slack'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'url': 'https://api.slack.com/web-hook-key'}

    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )

        self._provider = provider
        self._dispatcher = SlackOutput(None)

    def test_format_message_single(self):
        """SlackOutput - Format Single Message - Slack"""
        rule_name = 'test_rule_single'
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=SlackOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        loaded_message = SlackOutput._format_message(alert, alert_publication)

        # tests
        assert set(loaded_message.keys()) == {'text', 'mrkdwn', 'attachments'}
        assert (
            loaded_message['text'] ==
            '*StreamAlert Rule Triggered: test_rule_single*')
        assert len(loaded_message['attachments']) == 1

    def test_format_message_custom_text(self):
        """SlackOutput - Format Single Message - Custom Text"""
        rule_name = 'test_rule_single'
        alert = get_random_alert(25, rule_name)
        output = MagicMock(spec=SlackOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        alert_publication['@slack.text'] = 'Lorem ipsum foobar'

        loaded_message = SlackOutput._format_message(alert, alert_publication)

        # tests
        assert set(loaded_message.keys()) == {'text', 'mrkdwn', 'attachments'}
        assert loaded_message['text'] == 'Lorem ipsum foobar'
        assert len(loaded_message['attachments']) == 1

    def test_format_message_custom_attachment(self):
        """SlackOutput - Format Message, Custom Attachment"""
        rule_name = 'test_empty_rule_description'
        alert = get_random_alert(10, rule_name, True)
        output = MagicMock(spec=SlackOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        alert_publication['@slack.attachments'] = [
            {'text': 'aasdfkjadfj'}
        ]

        loaded_message = SlackOutput._format_message(alert, alert_publication)

        # tests
        assert len(loaded_message['attachments']) == 1
        assert loaded_message['attachments'][0]['text'] == 'aasdfkjadfj'

    @patch('logging.Logger.warning')
    def test_format_message_custom_attachment_limit(self, log_warning):
        """SlackOutput - Format Message, Custom Attachment is Truncated"""
        rule_name = 'test_empty_rule_description'
        alert = get_random_alert(10, rule_name, True)
        output = MagicMock(spec=SlackOutput)
        alert_publication = compose_alert(alert, output, 'asdf')

        long_message = 'a' * (SlackOutput.MAX_MESSAGE_SIZE + 1)
        alert_publication['@slack.attachments'] = [
            {'text': long_message}
        ]

        loaded_message = SlackOutput._format_message(alert, alert_publication)

        # tests
        assert len(loaded_message['attachments'][0]['text']) == 3999  # bug in elide
        log_warning.assert_called_with(
            'Custom attachment was truncated to length %d. Full message: %s',
            SlackOutput.MAX_MESSAGE_SIZE,
            long_message
        )

    def test_format_message_custom_attachment_multi(self):
        """SlackOutput - Format Message, Multiple Custom Attachments"""
        rule_name = 'test_empty_rule_description'
        alert = get_random_alert(10, rule_name, True)
        output = MagicMock(spec=SlackOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        alert_publication['@slack.attachments'] = [
            {'text': 'attachment text1'},
            {'text': 'attachment text2'},
        ]

        loaded_message = SlackOutput._format_message(alert, alert_publication)

        # tests
        assert len(loaded_message['attachments']) == 2
        assert loaded_message['attachments'][0]['text'] == 'attachment text1'
        assert loaded_message['attachments'][1]['text'] == 'attachment text2'

    @patch('logging.Logger.warning')
    def test_format_message_custom_attachment_multi_limit(self, log_warning):
        """SlackOutput - Format Message, Too many Custom Attachments is truncated"""
        rule_name = 'test_empty_rule_description'
        alert = get_random_alert(10, rule_name, True)
        output = MagicMock(spec=SlackOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        alert_publication['@slack.attachments'] = [{'text': 'yay'}
                                                   for _ in range(SlackOutput.MAX_ATTACHMENTS + 1)]

        loaded_message = SlackOutput._format_message(alert, alert_publication)

        # tests
        assert len(loaded_message['attachments']) == SlackOutput.MAX_ATTACHMENTS
        assert loaded_message['attachments'][19]['text'] == 'yay'
        log_warning.assert_called_with(
            'Message with %d custom attachments was truncated to %d attachments',
            SlackOutput.MAX_ATTACHMENTS + 1,
            SlackOutput.MAX_ATTACHMENTS
        )

    def test_format_message_multiple(self):
        """SlackOutput - Format Multi-Message"""
        rule_name = 'test_rule_multi-part'
        alert = get_random_alert(30, rule_name)
        output = MagicMock(spec=SlackOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        loaded_message = SlackOutput._format_message(alert, alert_publication)

        # tests
        assert set(loaded_message.keys()) == {'text', 'mrkdwn', 'attachments'}
        assert loaded_message['text'] == '*StreamAlert Rule Triggered: test_rule_multi-part*'
        assert len(loaded_message['attachments']) == 2
        assert loaded_message['attachments'][1]['text'].split('\n')[3][1:7] == '000028'

    def test_format_message_default_rule_description(self):
        """SlackOutput - Format Message, Default Rule Description"""
        rule_name = 'test_empty_rule_description'
        alert = get_random_alert(10, rule_name, True)
        output = MagicMock(spec=SlackOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        loaded_message = SlackOutput._format_message(alert, alert_publication)

        # tests
        default_rule_description = '*Rule Description:*\nNo rule description provided\n'
        assert loaded_message['attachments'][0]['pretext'] == default_rule_description

    def test_json_to_slack_mrkdwn_str(self):
        """SlackOutput - JSON to Slack mrkdwn, Simple String"""
        simple_str = 'value to format'
        result = SlackOutput._json_to_slack_mrkdwn(simple_str, 0)

        assert len(result) == 1
        assert result[0] == simple_str

    def test_json_to_slack_mrkdwn_dict(self):
        """SlackOutput - JSON to Slack mrkdwn, Simple Dict"""
        simple_dict = OrderedDict([('test_key_01', 'test_value_01'),
                                   ('test_key_02', 'test_value_02')])
        result = SlackOutput._json_to_slack_mrkdwn(simple_dict, 0)

        assert len(result) == 2
        assert result[1] == '*test_key_02:* test_value_02'

    def test_json_to_slack_mrkdwn_nested_dict(self):
        """SlackOutput - JSON to Slack mrkdwn, Nested Dict"""
        nested_dict = OrderedDict([
            ('root_key_01', 'root_value_01'),
            ('root_02', 'root_value_02'),
            ('root_nested_01', OrderedDict([
                ('nested_key_01', 100),
                ('nested_key_02', 200),
                ('nested_nested_01', OrderedDict([
                    ('nested_nested_key_01', 300)
                ]))
            ]))
        ])
        result = SlackOutput._json_to_slack_mrkdwn(nested_dict, 0)
        assert len(result) == 7
        assert result[2] == '*root_nested_01:*'
        assert Counter(result[4])['\t'] == 1
        assert Counter(result[6])['\t'] == 2

    def test_json_to_slack_mrkdwn_list(self):
        """SlackOutput - JSON to Slack mrkdwn, Simple List"""
        simple_list = ['test_value_01', 'test_value_02']
        result = SlackOutput._json_to_slack_mrkdwn(simple_list, 0)

        assert len(result) == 2
        assert result[0] == '*[1]* test_value_01'
        assert result[1] == '*[2]* test_value_02'

    def test_json_to_slack_mrkdwn_multi_nested(self):
        """SlackOutput - JSON to Slack mrkdwn, Multi-type Nested"""
        nested_dict = OrderedDict([
            ('root_key_01', 'root_value_01'),
            ('root_02', 'root_value_02'),
            ('root_nested_01', OrderedDict([
                ('nested_key_01', 100),
                ('nested_key_02', 200),
                ('nested_nested_01', OrderedDict([
                    ('nested_nested_key_01', [
                        6161,
                        1051,
                        51919
                    ])
                ]))
            ]))
        ])
        result = SlackOutput._json_to_slack_mrkdwn(nested_dict, 0)
        assert len(result) == 10
        assert result[2] == '*root_nested_01:*'
        assert Counter(result[4])['\t'] == 1
        assert result[-1] == '\t\t\t*[3]* 51919'

    def test_json_list_to_text(self):
        """SlackOutput - JSON list to text"""
        simple_list = ['test_value_01', 'test_value_02', {'nested': 'value_03'}]
        result = SlackOutput._json_list_to_text(simple_list, '\t', 0)

        assert len(result) == 4
        assert result[0] == '*[1]* test_value_01'
        assert result[1] == '*[2]* test_value_02'
        assert result[2] == '*[3]*'
        assert result[3] == '\t*nested:* value_03'

    def test_json_map_to_text(self):
        """SlackOutput - JSON map to text"""
        simple_dict = OrderedDict([('test_key_01', 'test_value_01'),
                                   ('test_key_02', 'test_value_02')])
        result = SlackOutput._json_map_to_text(simple_dict, '\t', 0)

        assert len(result) == 2
        assert result[1] == '*test_key_02:* test_value_02'

    def test_split_attachment_text_newline(self):
        """SlackOutput - Split Attachment, On Newline"""
        message = {'messages': 'test\n' * 800}
        result = list(SlackOutput._split_attachment_text(message))
        assert len(result[0]) == 3996

    def test_split_attachment_text_on_space(self):
        """SlackOutput - Split Attachment, On Space"""
        message = {'messages': 'test ' * 800}
        result = list(SlackOutput._split_attachment_text(message))
        assert len(result[0]) == 3996

    def test_split_attachment_text_no_delimiter(self):
        """SlackOutput - Split Attachment, No Delimiter"""
        message = {'messages': 'test' * 2000}
        result = list(SlackOutput._split_attachment_text(message))
        assert len(result[1]) == 4000

    @patch('logging.Logger.warning')
    def test_max_attachments(self, log_mock):
        """SlackOutput - Max Attachment Reached"""
        alert = get_alert()
        alert.record = {'info': 'test' * 20000}
        output = MagicMock(spec=SlackOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        SlackOutput._format_default_attachments(alert, alert_publication, 'foo')
        log_mock.assert_called_with(
            '%s: %d-part message truncated to %d parts',
            alert_publication,
            21,
            20
        )

    @patch('logging.Logger.info')
    @patch('requests.post')
    def test_dispatch_success(self, url_mock, log_mock):
        """SlackOutput - Dispatch Success"""
        url_mock.return_value.status_code = 200
        url_mock.return_value.json.return_value = {}

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    def test_dispatch_failure(self, url_mock, log_mock):
        """SlackOutput - Dispatch Failure, Bad Request"""
        json_error = {'message': 'error message', 'errors': ['error1']}
        url_mock.return_value.json.return_value = json_error
        url_mock.return_value.status_code = 400

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_mock):
        """SlackOutput - Dispatch Failure, Bad Descriptor"""
        assert not self._dispatcher.dispatch(
            get_alert(), ':'.join([self.SERVICE, 'bad_descriptor']))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, 'bad_descriptor')

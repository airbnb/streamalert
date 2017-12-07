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
# pylint: disable=protected-access,attribute-defined-outside-init,no-self-use
from collections import Counter, OrderedDict
from mock import patch
from moto import mock_s3, mock_kms
from nose.tools import assert_equal, assert_false, assert_true, assert_set_equal

from stream_alert.alert_processor.outputs.slack import SlackOutput
from stream_alert_cli.helpers import put_mock_creds
from tests.unit.stream_alert_alert_processor import CONFIG, FUNCTION_NAME, KMS_ALIAS, REGION
from tests.unit.stream_alert_alert_processor.helpers import (
    get_random_alert,
    get_alert,
    remove_temp_secrets
)


@mock_s3
@mock_kms
@patch('stream_alert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
class TestSlackOutput(object):
    """Test class for SlackOutput"""
    DESCRIPTOR = 'unit_test_channel'
    SERVICE = 'slack'
    CREDS = {'url': 'https://api.slack.com/web-hook-key'}

    def setup(self):
        """Setup before each method"""
        self._dispatcher = SlackOutput(REGION, FUNCTION_NAME, CONFIG)
        remove_temp_secrets()
        output_name = self._dispatcher.output_cred_name(self.DESCRIPTOR)
        put_mock_creds(output_name, self.CREDS, self._dispatcher.secrets_bucket, REGION, KMS_ALIAS)

    def test_format_message_single(self):
        """SlackOutput - Format Single Message - Slack"""
        rule_name = 'test_rule_single'
        alert = get_random_alert(25, rule_name)
        loaded_message = SlackOutput._format_message(rule_name, alert)

        # tests
        assert_set_equal(set(loaded_message.keys()), {'text', 'mrkdwn', 'attachments'})
        assert_equal(
            loaded_message['text'],
            '*StreamAlert Rule Triggered: test_rule_single*')
        assert_equal(len(loaded_message['attachments']), 1)

    def test_format_message_mutliple(self):
        """SlackOutput - Format Multi-Message"""
        rule_name = 'test_rule_multi-part'
        alert = get_random_alert(30, rule_name)
        loaded_message = SlackOutput._format_message(rule_name, alert)

        # tests
        assert_set_equal(set(loaded_message.keys()), {'text', 'mrkdwn', 'attachments'})
        assert_equal(loaded_message['text'], '*StreamAlert Rule Triggered: test_rule_multi-part*')
        assert_equal(len(loaded_message['attachments']), 2)
        assert_equal(loaded_message['attachments'][1]['text'].split('\n')[3][1:7], '000028')

    def test_format_message_default_rule_description(self):
        """SlackOutput - Format Message, Default Rule Description"""
        rule_name = 'test_empty_rule_description'
        alert = get_random_alert(10, rule_name, True)
        loaded_message = SlackOutput._format_message(rule_name, alert)

        # tests
        default_rule_description = '*Rule Description:*\nNo rule description provided\n'
        assert_equal(loaded_message['attachments'][0]['pretext'], default_rule_description)

    def test_json_to_slack_mrkdwn_str(self):
        """SlackOutput - JSON to Slack mrkdwn, Simple String"""
        simple_str = 'value to format'
        result = SlackOutput._json_to_slack_mrkdwn(simple_str, 0)

        assert_equal(len(result), 1)
        assert_equal(result[0], simple_str)

    def test_json_to_slack_mrkdwn_dict(self):
        """SlackOutput - JSON to Slack mrkdwn, Simple Dict"""
        simple_dict = OrderedDict([('test_key_01', 'test_value_01'),
                                   ('test_key_02', 'test_value_02')])
        result = SlackOutput._json_to_slack_mrkdwn(simple_dict, 0)

        assert_equal(len(result), 2)
        assert_equal(result[1], '*test_key_02:* test_value_02')

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
        assert_equal(len(result), 7)
        assert_equal(result[2], '*root_nested_01:*')
        assert_equal(Counter(result[4])['\t'], 1)
        assert_equal(Counter(result[6])['\t'], 2)

    def test_json_to_slack_mrkdwn_list(self):
        """SlackOutput - JSON to Slack mrkdwn, Simple List"""
        simple_list = ['test_value_01', 'test_value_02']
        result = SlackOutput._json_to_slack_mrkdwn(simple_list, 0)

        assert_equal(len(result), 2)
        assert_equal(result[0], '*[1]* test_value_01')
        assert_equal(result[1], '*[2]* test_value_02')

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
        assert_equal(len(result), 10)
        assert_equal(result[2], '*root_nested_01:*')
        assert_equal(Counter(result[4])['\t'], 1)
        assert_equal(result[-1], '\t\t\t*[3]* 51919')

    def test_json_list_to_text(self):
        """SlackOutput - JSON list to text"""
        simple_list = ['test_value_01', 'test_value_02', {'nested': 'value_03'}]
        result = SlackOutput._json_list_to_text(simple_list, '\t', 0)

        assert_equal(len(result), 4)
        assert_equal(result[0], '*[1]* test_value_01')
        assert_equal(result[1], '*[2]* test_value_02')
        assert_equal(result[2], '*[3]*')
        assert_equal(result[3], '\t*nested:* value_03')

    def test_json_map_to_text(self):
        """SlackOutput - JSON map to text"""
        simple_dict = OrderedDict([('test_key_01', 'test_value_01'),
                                   ('test_key_02', 'test_value_02')])
        result = SlackOutput._json_map_to_text(simple_dict, '\t', 0)

        assert_equal(len(result), 2)
        assert_equal(result[1], '*test_key_02:* test_value_02')

    @patch('logging.Logger.info')
    @patch('requests.post')
    def test_dispatch_success(self, url_mock, log_mock):
        """SlackOutput - Dispatch Success"""
        url_mock.return_value.status_code = 200
        url_mock.return_value.json.return_value = dict()

        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert()))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    @patch('logging.Logger.error')
    @patch('requests.post')
    def test_dispatch_failure(self, url_mock, log_mock):
        """SlackOutput - Dispatch Failure, Bad Request"""
        json_error = {'message': 'error message', 'errors': ['error1']}
        url_mock.return_value.json.return_value = json_error
        url_mock.return_value.status_code = 400

        assert_false(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                               rule_name='rule_name',
                                               alert=get_alert()))

        log_mock.assert_called_with('Failed to send alert to %s', self.SERVICE)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_mock):
        """SlackOutput - Dispatch Failure, Bad Descriptor"""
        assert_false(self._dispatcher.dispatch(descriptor='bad_descriptor',
                                               rule_name='rule_name',
                                               alert=get_alert()))

        log_mock.assert_called_with('Failed to send alert to %s', self.SERVICE)

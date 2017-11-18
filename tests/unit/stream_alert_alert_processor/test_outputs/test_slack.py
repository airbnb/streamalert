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
# pylint: disable=protected-access
from collections import Counter, OrderedDict
import json
from mock import patch
from moto import mock_s3, mock_kms
from nose.tools import (
    assert_equal,
    assert_set_equal
)

from stream_alert.alert_processor.outputs.output_base import StreamAlertOutput
from stream_alert_cli.helpers import put_mock_creds
from tests.unit.stream_alert_alert_processor import CONFIG, FUNCTION_NAME, KMS_ALIAS, REGION
from tests.unit.stream_alert_alert_processor.helpers import (
    get_random_alert,
    get_alert,
    remove_temp_secrets
)


class TestSlackOutput(object):
    """Test class for SlackOutput"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.__service = 'slack'
        cls.__descriptor = 'unit_test_channel'
        cls.__dispatcher = StreamAlertOutput.create_dispatcher(cls.__service,
                                                               REGION,
                                                               FUNCTION_NAME,
                                                               CONFIG)

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.__dispatcher = None

    def test_format_message_single(self):
        """Format Single Message - Slack"""
        rule_name = 'test_rule_single'
        alert = get_random_alert(25, rule_name)
        loaded_message = self.__dispatcher._format_message(rule_name, alert)

        # tests
        assert_set_equal(set(loaded_message.keys()), {'text', 'mrkdwn', 'attachments'})
        assert_equal(
            loaded_message['text'],
            '*StreamAlert Rule Triggered: test_rule_single*')
        assert_equal(len(loaded_message['attachments']), 1)

    def test_format_message_mutliple(self):
        """Format Multi-Message - Slack"""
        rule_name = 'test_rule_multi-part'
        alert = get_random_alert(30, rule_name)
        loaded_message = self.__dispatcher._format_message(rule_name, alert)

        # tests
        assert_set_equal(set(loaded_message.keys()), {'text', 'mrkdwn', 'attachments'})
        assert_equal(
            loaded_message['text'],
            '*StreamAlert Rule Triggered: test_rule_multi-part*')
        assert_equal(len(loaded_message['attachments']), 2)
        assert_equal(loaded_message['attachments'][1]
                     ['text'].split('\n')[3][1:7], '000028')

    def test_format_message_default_rule_description(self):
        """Format Message Default Rule Description - Slack"""
        rule_name = 'test_empty_rule_description'
        alert = get_random_alert(10, rule_name, True)
        loaded_message = self.__dispatcher._format_message(rule_name, alert)

        # tests
        default_rule_description = '*Rule Description:*\nNo rule description provided\n'
        assert_equal(
            loaded_message['attachments'][0]['pretext'],
            default_rule_description)

    def test_json_to_slack_mrkdwn_str(self):
        """JSON to Slack mrkdwn - simple str"""
        simple_str = 'value to format'
        result = self.__dispatcher._json_to_slack_mrkdwn(simple_str, 0)

        assert_equal(len(result), 1)
        assert_equal(result[0], simple_str)

    def test_json_to_slack_mrkdwn_dict(self):
        """JSON to Slack mrkdwn - simple dict"""
        simple_dict = OrderedDict([('test_key_01', 'test_value_01'),
                                   ('test_key_02', 'test_value_02')])
        result = self.__dispatcher._json_to_slack_mrkdwn(simple_dict, 0)

        assert_equal(len(result), 2)
        assert_equal(result[1], '*test_key_02:* test_value_02')

    def test_json_to_slack_mrkdwn_nested_dict(self):
        """JSON to Slack mrkdwn - nested dict"""
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
        result = self.__dispatcher._json_to_slack_mrkdwn(nested_dict, 0)
        assert_equal(len(result), 7)
        assert_equal(result[2], '*root_nested_01:*')
        assert_equal(Counter(result[4])['\t'], 1)
        assert_equal(Counter(result[6])['\t'], 2)

    def test_json_to_slack_mrkdwn_list(self):
        """JSON to Slack mrkdwn - simple list"""
        simple_list = ['test_value_01', 'test_value_02']
        result = self.__dispatcher._json_to_slack_mrkdwn(simple_list, 0)

        assert_equal(len(result), 2)
        assert_equal(result[0], '*[1]* test_value_01')
        assert_equal(result[1], '*[2]* test_value_02')

    def test_json_to_slack_mrkdwn_multi_nested(self):
        """JSON to Slack mrkdwn - multi type nested"""
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
        result = self.__dispatcher._json_to_slack_mrkdwn(nested_dict, 0)
        assert_equal(len(result), 10)
        assert_equal(result[2], '*root_nested_01:*')
        assert_equal(Counter(result[4])['\t'], 1)
        assert_equal(result[-1], '\t\t\t*[3]* 51919')

    def test_json_list_to_text(self):
        """JSON list to text"""
        simple_list = ['test_value_01', 'test_value_02']
        result = self.__dispatcher._json_list_to_text(simple_list, '\t', 0)

        assert_equal(len(result), 2)
        assert_equal(result[0], '*[1]* test_value_01')
        assert_equal(result[1], '*[2]* test_value_02')

    def test_json_map_to_text(self):
        """JSON map to text"""
        simple_dict = OrderedDict([('test_key_01', 'test_value_01'),
                                   ('test_key_02', 'test_value_02')])
        result = self.__dispatcher._json_map_to_text(simple_dict, '\t', 0)

        assert_equal(len(result), 2)
        assert_equal(result[1], '*test_key_02:* test_value_02')

    def _setup_dispatch(self):
        """Helper for setting up SlackOutput dispatch"""
        remove_temp_secrets()

        output_name = self.__dispatcher.output_cred_name(self.__descriptor)

        creds = {'url': 'https://api.slack.com/web-hook-key'}

        put_mock_creds(output_name, creds, self.__dispatcher.secrets_bucket,
                       REGION, KMS_ALIAS)

        return get_alert()

    @patch('logging.Logger.info')
    @patch('requests.post')
    @mock_s3
    @mock_kms
    def test_dispatch_success(self, url_mock, log_info_mock):
        """SlackOutput dispatch success"""
        alert = self._setup_dispatch()
        url_mock.return_value.status_code = 200
        url_mock.return_value.json.return_value = json.loads('{}')

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_info_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.error')
    @patch('requests.post')
    @mock_s3
    @mock_kms
    def test_dispatch_failure(self, url_mock, log_error_mock):
        """SlackOutput dispatch failure"""
        alert = self._setup_dispatch()
        json_error = json.loads('{"message": "error message", "errors": ["error1"]}')
        url_mock.return_value.json.return_value = json_error
        url_mock.return_value.status_code = 400

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_error_mock.assert_called_with('Failed to send alert to %s', self.__service)

    @patch('logging.Logger.error')
    @mock_s3
    @mock_kms
    def test_dispatch_bad_descriptor(self, log_error_mock):
        """SlackOutput dispatch bad descriptor"""
        alert = self._setup_dispatch()
        self.__dispatcher.dispatch(descriptor='bad_descriptor',
                                   rule_name='rule_name',
                                   alert=alert)

        log_error_mock.assert_called_with('Failed to send alert to %s', self.__service)

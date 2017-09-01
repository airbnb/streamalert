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

import boto3
from mock import call, patch
from moto import mock_s3, mock_kms, mock_lambda
from nose.tools import (
    assert_equal,
    assert_is_none,
    assert_is_not_none,
    assert_set_equal
)

from stream_alert.alert_processor import outputs
from stream_alert.alert_processor.output_base import OutputProperty
from stream_alert_cli.helpers import create_lambda_function, put_mock_creds
from tests.unit.stream_alert_alert_processor import CONFIG, FUNCTION_NAME, KMS_ALIAS, REGION
from tests.unit.stream_alert_alert_processor.helpers import (
    get_random_alert,
    get_alert,
    remove_temp_secrets
)


def test_existing_get_output_dispatcher():
    """Get output dispatcher - existing"""
    service = 'aws-s3'
    dispatcher = outputs.get_output_dispatcher(
        service, REGION, FUNCTION_NAME, CONFIG)
    assert_is_not_none(dispatcher)


def test_nonexistent_get_output_dispatcher():
    """Get output dispatcher - nonexistent"""
    nonexistent_service = 'aws-s4'
    dispatcher = outputs.get_output_dispatcher(nonexistent_service,
                                               REGION,
                                               FUNCTION_NAME,
                                               CONFIG)
    assert_is_none(dispatcher)


@patch('logging.Logger.error')
def test_get_output_dispatcher_logging(log_mock):
    """Get output dispatcher - log error"""
    bad_service = 'bad-output'
    outputs.get_output_dispatcher(bad_service, REGION, FUNCTION_NAME, CONFIG)
    log_mock.assert_called_with(
        'designated output service [%s] does not exist',
        bad_service)


def test_user_defined_properties():
    """Get user defined properties"""
    for output in outputs.STREAM_OUTPUTS.values():
        props = output(REGION, FUNCTION_NAME, CONFIG).get_user_defined_properties()
        # The user defined properties should at a minimum contain a descriptor
        assert_is_not_none(props.get('descriptor'))


class TestPagerDutyOutput(object):
    """Test class for PagerDutyOutput"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.__service = 'pagerduty'
        cls.__descriptor = 'unit_test_pagerduty'
        cls.__backup_method = None
        cls.__dispatcher = outputs.get_output_dispatcher(cls.__service,
                                                         REGION,
                                                         FUNCTION_NAME,
                                                         CONFIG)

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.__dispatcher = None

    def test_get_default_properties(self):
        """Get Default Properties - PagerDuty"""
        props = self.__dispatcher._get_default_properties()
        assert_equal(len(props), 1)
        assert_equal(props['url'],
                     'https://events.pagerduty.com/generic/2010-04-15/create_event.json')

    def _setup_dispatch(self):
        """Helper for setting up PagerDutyOutput dispatch"""
        remove_temp_secrets()

        # Cache the _get_default_properties and set it to return None
        self.__backup_method = self.__dispatcher._get_default_properties
        self.__dispatcher._get_default_properties = lambda: None

        output_name = self.__dispatcher.output_cred_name(self.__descriptor)

        creds = {'url': 'http://pagerduty.foo.bar/create_event.json',
                 'service_key': 'mocked_service_key'}

        put_mock_creds(output_name, creds, self.__dispatcher.secrets_bucket, REGION, KMS_ALIAS)

        return get_alert()

    def _teardown_dispatch(self):
        """Replace method with cached method"""
        self.__dispatcher._get_default_properties = self.__backup_method

    @patch('logging.Logger.info')
    @patch('urllib2.urlopen')
    @mock_s3
    @mock_kms
    def test_dispatch_success(self, url_mock, log_info_mock):
        """PagerDutyOutput dispatch success"""
        alert = self._setup_dispatch()
        url_mock.return_value.getcode.return_value = 200

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_info_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.error')
    @patch('urllib2.urlopen')
    @mock_s3
    @mock_kms
    def test_dispatch_failure(self, url_mock, log_error_mock):
        """PagerDutyOutput dispatch failure"""
        alert = self._setup_dispatch()
        bad_message = '{"error": {"message": "failed", "errors": ["err1", "err2"]}}'
        url_mock.return_value.read.return_value = bad_message
        url_mock.return_value.getcode.return_value = 400

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_error_mock.assert_called_with('Failed to send alert to %s', self.__service)

    @patch('logging.Logger.error')
    @mock_s3
    @mock_kms
    def test_dispatch_bad_descriptor(self, log_error_mock):
        """PagerDutyOutput dispatch bad descriptor"""
        alert = self._setup_dispatch()
        self.__dispatcher.dispatch(descriptor='bad_descriptor',
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_error_mock.assert_called_with('Failed to send alert to %s', self.__service)


@mock_s3
@mock_kms
class TestPhantomOutput(object):
    """Test class for PhantomOutput"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.__service = 'phantom'
        cls.__descriptor = 'unit_test_phantom'
        cls.__dispatcher = outputs.get_output_dispatcher(cls.__service,
                                                         REGION,
                                                         FUNCTION_NAME,
                                                         CONFIG)

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.__dispatcher = None

    def _setup_dispatch(self, url):
        """Helper for setting up PhantomOutput dispatch"""
        remove_temp_secrets()

        output_name = self.__dispatcher.output_cred_name(self.__descriptor)

        creds = {'url': url,
                 'ph_auth_token': 'mocked_auth_token'}

        put_mock_creds(output_name, creds, self.__dispatcher.secrets_bucket, REGION, KMS_ALIAS)

        return get_alert()

    @patch('logging.Logger.info')
    @patch('urllib2.urlopen')
    def test_dispatch_existing_container(self, url_mock, log_mock):
        """PhantomOutput dispatch success, existing container"""
        alert = self._setup_dispatch('phantom.foo.bar')
        url_mock.return_value.getcode.return_value = 200
        url_mock.return_value.read.side_effect = ['{"count": 1, "data": [{"id": 1948}]}']

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.info')
    @patch('urllib2.urlopen')
    def test_dispatch_new_container(self, url_mock, log_mock):
        """PhantomOutput dispatch success, new container"""
        alert = self._setup_dispatch('phantom.foo.bar')
        url_mock.return_value.getcode.return_value = 200
        url_mock.return_value.read.side_effect = ['{"count": 0, "data": []}', '{"id": 1948}']

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.error')
    @patch('urllib2.urlopen')
    def test_dispatch_container_failure(self, url_mock, log_mock):
        """PhantomOutput dispatch failure (setup container)"""
        alert = self._setup_dispatch('phantom.foo.bar')
        url_mock.return_value.getcode.return_value = 400
        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('Failed to send alert to %s', self.__service)

    @patch('logging.Logger.error')
    @patch('urllib2.urlopen')
    def test_dispatch_container_error(self, url_mock, log_mock):
        """PhantomOutput dispatch decode error (setup container)"""
        alert = self._setup_dispatch('phantom.foo.bar')
        url_mock.return_value.getcode.return_value = 200
        url_mock.return_value.read.return_value = 'this\nis\nnot\njson'

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        response = str(
            call('An error occurred while decoding '
                 'Phantom container query response to JSON: %s', ValueError(
                     'No JSON object could be decoded',)))

        assert_equal(str(log_mock.call_args_list[0]), response)

    @patch('logging.Logger.error')
    @patch('urllib2.urlopen')
    def test_dispatch_failure(self, url_mock, log_mock):
        """PhantomOutput dispatch failure (artifact)"""
        alert = self._setup_dispatch('phantom.foo.bar')
        url_mock.return_value.read.side_effect = ['', '{"id": 1902}']
        # Use side_effect to change the getcode return value the second time
        # it is called. This allows testing issues down the chain somewhere
        url_mock.return_value.getcode.side_effect = [200, 400]
        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('Failed to send alert to %s', self.__service)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_error_mock):
        """PhantomOutput dispatch bad descriptor"""
        alert = self._setup_dispatch('phantom.foo.bar')
        self.__dispatcher.dispatch(descriptor='bad_descriptor',
                                   rule_name='rule_name',
                                   alert=alert)

        log_error_mock.assert_called_with('Failed to send alert to %s', self.__service)

    @patch('stream_alert.alert_processor.output_base.StreamOutputBase._request_helper')
    def test_dispatch_container_query(self, request_mock):
        """PhantomOutput - Container Query URL"""
        alert = self._setup_dispatch('phantom.foo.bar')
        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        full_url = 'phantom.foo.bar/rest/container?_filter_name="rule_name"&page_size=1'
        headers = {'ph-auth-token': 'mocked_auth_token'}
        request_mock.assert_has_calls([call(full_url, None, headers, False)])


class TestSlackOutput(object):
    """Test class for PagerDutyOutput"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.__service = 'slack'
        cls.__descriptor = 'unit_test_channel'
        cls.__dispatcher = outputs.get_output_dispatcher(cls.__service,
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
        loaded_message = json.loads(self.__dispatcher._format_message(rule_name, alert))

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
        loaded_message = json.loads(self.__dispatcher._format_message(rule_name, alert))

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
        loaded_message = json.loads(self.__dispatcher._format_message(rule_name, alert))

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
    @patch('urllib2.urlopen')
    @mock_s3
    @mock_kms
    def test_dispatch_success(self, url_mock, log_info_mock):
        """SlackOutput dispatch success"""
        alert = self._setup_dispatch()
        url_mock.return_value.getcode.return_value = 200

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_info_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.error')
    @patch('urllib2.urlopen')
    @mock_s3
    @mock_kms
    def test_dispatch_failure(self, url_mock, log_error_mock):
        """SlackOutput dispatch failure"""
        alert = self._setup_dispatch()
        error_message = 'a helpful error message'
        url_mock.return_value.read.return_value = error_message
        url_mock.return_value.getcode.return_value = 400

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_error_mock.assert_any_call('Encountered an error while sending to Slack: %s',
                                       error_message)
        log_error_mock.assert_any_call('Failed to send alert to %s', self.__service)

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


class TestAWSOutput(object):
    """Test class for AWSOutput Base"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        # pylint: disable=abstract-class-instantiated
        cls.__abstractmethods_cache = outputs.AWSOutput.__abstractmethods__
        outputs.AWSOutput.__abstractmethods__ = frozenset()
        cls.__dispatcher = outputs.AWSOutput(REGION, FUNCTION_NAME, CONFIG)
        cls.__dispatcher.__service__ = 'aws-s3'

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        outputs.AWSOutput.__abstractmethods__ = cls.__abstractmethods_cache
        cls.__dispatcher = None

    def test_aws_format_output_config(self):
        """AWSOutput format output config"""
        props = {
            'descriptor': OutputProperty(
                'short_descriptor',
                'descriptor_value'),
            'aws_value': OutputProperty(
                'unique arn value, bucket, etc',
                'bucket.value')}

        formatted_config = self.__dispatcher.format_output_config(CONFIG, props)

        assert_equal(len(formatted_config), 2)
        assert_is_not_none(formatted_config.get('descriptor_value'))
        assert_is_not_none(formatted_config.get('unit_test_bucket'))

    def test_dispatch(self):
        """AWSOutput dispatch pass"""
        passed = self.__dispatcher.dispatch()
        assert_is_none(passed)


class TestS3Ouput(object):
    """Test class for S3Output"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.__service = 'aws-s3'
        cls.__descriptor = 'unit_test_bucket'
        cls.__dispatcher = outputs.get_output_dispatcher(cls.__service,
                                                         REGION,
                                                         FUNCTION_NAME,
                                                         CONFIG)

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.dispatcher = None

    def test_locals(self):
        """S3Output local variables"""
        assert_equal(self.__dispatcher.__class__.__name__, 'S3Output')
        assert_equal(self.__dispatcher.__service__, self.__service)

    def _setup_dispatch(self):
        """Helper for setting up S3Output dispatch"""
        bucket = CONFIG[self.__service][self.__descriptor]
        boto3.client('s3', region_name=REGION).create_bucket(Bucket=bucket)

        return get_alert()

    @patch('logging.Logger.info')
    @mock_s3
    def test_dispatch(self, log_mock):
        """S3Output dispatch"""
        alert = self._setup_dispatch()
        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('Successfully sent alert to %s', self.__service)


class TestLambdaOuput(object):
    """Test class for LambdaOutput"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.__service = 'aws-lambda'
        cls.__descriptor = 'unit_test_lambda'
        cls.__dispatcher = outputs.get_output_dispatcher(cls.__service,
                                                         REGION,
                                                         FUNCTION_NAME,
                                                         CONFIG)

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.dispatcher = None

    def test_locals(self):
        """LambdaOutput local variables"""
        assert_equal(self.__dispatcher.__class__.__name__, 'LambdaOutput')
        assert_equal(self.__dispatcher.__service__, self.__service)

    def _setup_dispatch(self, alt_descriptor=''):
        """Helper for setting up LambdaOutput dispatch"""
        function_name = CONFIG[self.__service][alt_descriptor or self.__descriptor]
        create_lambda_function(function_name, REGION)
        return get_alert()

    @mock_lambda
    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """LambdaOutput dispatch"""
        alert = self._setup_dispatch()
        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @mock_lambda
    @patch('logging.Logger.info')
    def test_dispatch_with_qualifier(self, log_mock):
        """LambdaOutput dispatch with qualifier"""
        alt_descriptor = '{}_qual'.format(self.__descriptor)
        alert = self._setup_dispatch(alt_descriptor)
        self.__dispatcher.dispatch(descriptor=alt_descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('Successfully sent alert to %s', self.__service)

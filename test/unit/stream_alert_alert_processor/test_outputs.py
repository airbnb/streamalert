'''
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
'''
import random
import urllib2
import zipfile

from collections import OrderedDict, Counter
from StringIO import StringIO

from mock import call, patch
from moto import mock_s3, mock_kms, mock_lambda
from nose.tools import (
    assert_equal,
    assert_is_none,
    assert_is_not_none,
    assert_not_equal,
    assert_set_equal,
    with_setup
)

from stream_alert.alert_processor import outputs as outputs
from stream_alert.alert_processor.outputs import *

from stream_alert.alert_processor.main import _load_output_config as load_config
from stream_alert.alert_processor.output_base import OutputProperty

from unit.stream_alert_alert_processor import (
    REGION,
    FUNCTION_NAME,
    CONFIG
)

from unit.stream_alert_alert_processor.helpers import (
    _get_alert,
    _encrypt_with_kms,
    _put_mock_creds,
    _put_s3_test_object
)

UNIT_CONFIG = load_config('test/unit/conf/outputs.json')


def test_existing_get_output_dispatcher():
    """Get output dispatcher - existing"""
    service = 'aws-s3'
    dispatcher = outputs.get_output_dispatcher(service, REGION, FUNCTION_NAME, UNIT_CONFIG)
    assert_is_not_none(dispatcher)

def test_nonexistent_get_output_dispatcher():
    """Get output dispatcher - nonexistent"""
    nonexistent_service = 'aws-s4'
    dispatcher = outputs.get_output_dispatcher(nonexistent_service,
                                               REGION,
                                               FUNCTION_NAME,
                                               UNIT_CONFIG)
    assert_is_none(dispatcher)

@patch('logging.Logger.error')
def test_get_output_dispatcher_logging(log_mock):
    """Get output dispatcher - log error"""
    bad_service = 'bad-output'
    outputs.get_output_dispatcher(bad_service, REGION, FUNCTION_NAME, UNIT_CONFIG)
    log_mock.assert_called_with('designated output service [%s] does not exist', bad_service)


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
        cls.__service = 'pagerduty'
        cls.__descriptor = 'unit_test_pagerduty'
        cls.__backup_method = None
        """Setup the class before any methods"""
        cls.__dispatcher = outputs.get_output_dispatcher(cls.__service,
                                                         REGION,
                                                         FUNCTION_NAME,
                                                         UNIT_CONFIG)
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
        # Cache the _get_default_properties and set it to return None
        self.__backup_method = self.__dispatcher._get_default_properties
        self.__dispatcher._get_default_properties = lambda: None

        output_name = self.__dispatcher.output_cred_name(self.__descriptor)

        creds = {'url': 'http://pagerduty.foo.bar/create_event.json',
                 'service_key': 'mocked_service_key'}

        _put_mock_creds(output_name, creds, self.__dispatcher.secrets_bucket)

        return _get_alert(0)['default']

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

        log_info_mock.assert_called_with('successfully sent alert to %s', self.__service)

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

        log_error_mock.assert_called_with('failed to send alert to %s', self.__service)

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

        log_error_mock.assert_called_with('failed to send alert to %s', self.__service)


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
                                                         UNIT_CONFIG)
    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.__dispatcher = None

    def _setup_dispatch(self, url):
        """Helper for setting up PhantomOutput dispatch"""
        output_name = self.__dispatcher.output_cred_name(self.__descriptor)

        creds = {'url': url,
                 'ph_auth_token': 'mocked_auth_token'}

        _put_mock_creds(output_name, creds, self.__dispatcher.secrets_bucket)

        return _get_alert(0)['default']

    @patch('logging.Logger.info')
    @patch('urllib2.urlopen')
    @mock_s3
    @mock_kms
    def test_dispatch(self, url_mock, log_mock):
        """PhantomOutput dispatch success"""
        alert = self._setup_dispatch('phantom.foo.bar')
        url_mock.return_value.getcode.return_value = 200
        url_mock.return_value.read.return_value = '{"id": 1948}'

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('successfully sent alert to %s', self.__service)

    @patch('logging.Logger.error')
    @patch('urllib2.urlopen')
    @mock_s3
    @mock_kms
    def test_dispatch_container_failure(self, url_mock, log_mock):
        """PhantomOutput dispatch failure (setup container)"""
        alert = self._setup_dispatch('phantom.foo.bar')
        url_mock.return_value.getcode.return_value = 400
        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('failed to send alert to %s', self.__service)

    @patch('logging.Logger.error')
    @patch('urllib2.urlopen')
    @mock_s3
    @mock_kms
    def test_dispatch_container_error(self, url_mock, log_mock):
        """PhantomOutput dispatch decode error (setup container)"""
        alert = self._setup_dispatch('phantom.foo.bar')
        url_mock.return_value.getcode.return_value = 200
        url_mock.return_value.read.return_value = 'this\nis\nnot\njson'

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        assert_equal(str(log_mock.call_args_list[0]),
                     str(call('An error occurred while decoding phantom response to JSON: %s',
                              ValueError('No JSON object could be decoded',))))

    @patch('logging.Logger.error')
    @patch('urllib2.urlopen')
    @mock_s3
    @mock_kms
    def test_dispatch_failure(self, url_mock, log_mock):
        """PhantomOutput dispatch failure (artifact)"""
        alert = self._setup_dispatch('phantom.foo.bar')
        url_mock.return_value.read.return_value = '{"id": 1902}'
        # Use side_effect to change the getcode return value the second time
        # it is called. This allows testing issues down the chain somewhere
        url_mock.return_value.getcode.side_effect = [200, 400]
        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('failed to send alert to %s', self.__service)

    @patch('logging.Logger.error')
    @mock_s3
    @mock_kms
    def test_dispatch_bad_descriptor(self, log_error_mock):
        """PhantomOutput dispatch bad descriptor"""
        alert = self._setup_dispatch('phantom.foo.bar')
        self.__dispatcher.dispatch(descriptor='bad_descriptor',
                                   rule_name='rule_name',
                                   alert=alert)

        log_error_mock.assert_called_with('failed to send alert to %s', self.__service)


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
                                                         UNIT_CONFIG)
    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.__dispatcher = None

    @staticmethod
    def _get_random_alert(key_count, rule_name, omit_rule_desc=False):
        """This loop generates key/value pairs with a key of length 6 and
            value of length 148. when formatted, each line should consume
            160 characters, account for newline and asterisk for bold. For example:
            '*000001:* 6D829150B0154BF9BAC733FD25C61FA3D8CD3868AC2A92F19EEE119B
            9CE8D6094966AA7592CE371002F1F7D82617673FCC9A9DB2A8F432AA791D74AB80BBCAD9\n'
            Therefore, 25*160 = 4000 character message size (exactly the 4000 limit)
            Anything over 4000 characters will result in multi-part slack messages:
            55*160 = 8800 & 8800/4000 = ceil(2.2) = 3 messages needed
        """
        values = OrderedDict([('{:06}'.format(key),
                               '{:0148X}'.format(random.randrange(16**128)))
                              for key in range(key_count)])

        rule_description = ('rule test description', '')[omit_rule_desc]
        alert = {
            'record': values,
            'metadata': {
                'rule_name': rule_name,
                'rule_description': rule_description
            }
        }

        return alert

    def test_format_message_single(self):
        """Format Single Message - Slack"""
        rule_name = 'test_rule_single'
        alert = self._get_random_alert(25, rule_name)
        loaded_message = json.loads(self.__dispatcher._format_message(rule_name, alert))

        # tests
        assert_set_equal(set(loaded_message.keys()), {'text', 'mrkdwn', 'attachments'})
        assert_equal(loaded_message['text'], '*StreamAlert Rule Triggered: test_rule_single*')
        assert_equal(len(loaded_message['attachments']), 1)

    def test_format_message_mutliple(self):
        """Format Multi-Message - Slack"""
        rule_name = 'test_rule_multi-part'
        alert = self._get_random_alert(30, rule_name)
        loaded_message = json.loads(self.__dispatcher._format_message(rule_name, alert))

        # tests
        assert_set_equal(set(loaded_message.keys()), {'text', 'mrkdwn', 'attachments'})
        assert_equal(loaded_message['text'], '*StreamAlert Rule Triggered: test_rule_multi-part*')
        assert_equal(len(loaded_message['attachments']), 2)
        assert_equal(loaded_message['attachments'][1]['text'].split('\n')[3][1:7], '000028')

    def test_format_message_default_rule_description(self):
        """Format Message Default Rule Description - Slack"""
        rule_name = 'test_empty_rule_description'
        alert = self._get_random_alert(10, rule_name, True)
        loaded_message = json.loads(self.__dispatcher._format_message(rule_name, alert))

        # tests
        default_rule_description = '*Rule Description:*\nNo rule description provided\n'
        assert_equal(loaded_message['attachments'][0]['pretext'], default_rule_description)

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


class TestAWSOutput(object):
    """Test class for AWSOutput Base"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.__abstractmethods_cache = outputs.AWSOutput.__abstractmethods__
        outputs.AWSOutput.__abstractmethods__ = frozenset()
        cls.__dispatcher = outputs.AWSOutput(REGION, FUNCTION_NAME, UNIT_CONFIG)
        cls.__dispatcher.__service__ = 'aws-s3'

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        outputs.AWSOutput.__abstractmethods__ = cls.__abstractmethods_cache
        cls.__dispatcher = None

    def test_aws_format_output_config(self):
        """AWSOutput format output config"""

        props = {'descriptor': OutputProperty('short_descriptor', 'descriptor_value'),
                 'aws_value': OutputProperty('unique arn value, bucket, etc', 'bucket.value')}

        formatted_config = self.__dispatcher.format_output_config(UNIT_CONFIG, props)

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
                                                         UNIT_CONFIG)

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
        bucket = UNIT_CONFIG[self.__service][self.__descriptor]
        boto3.client('s3', region_name=REGION).create_bucket(Bucket=bucket)

        return _get_alert(0)['default']

    @patch('logging.Logger.info')
    @mock_s3
    def test_dispatch(self, log_mock):
        """S3Output dispatch"""
        alert = self._setup_dispatch()
        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('successfully sent alert to %s', self.__service)


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
                                                         UNIT_CONFIG)

    @classmethod
    def _make_lambda_package(cls):
        """Helper function to create mock lambda package"""
        mock_lambda_function = """
def handler(event, context):
    return event
"""
        package_output = StringIO()
        package = zipfile.ZipFile(package_output, 'w', zipfile.ZIP_DEFLATED)
        package.writestr('function.zip', mock_lambda_function)
        package.close()
        package_output.seek(0)

        return package_output.read()

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.dispatcher = None

    def test_locals(self):
        """LambdaOutput local variables"""
        assert_equal(self.__dispatcher.__class__.__name__, 'LambdaOutput')
        assert_equal(self.__dispatcher.__service__, self.__service)

    def _create_lambda_function(self):
        """Helper function to create mock lambda function"""
        function_name = UNIT_CONFIG[self.__service][self.__descriptor]

        boto3.client('lambda', region_name=REGION).create_function(
            FunctionName=function_name,
            Runtime='python2.7',
            Role='test-iam-role',
            Handler='function.handler',
            Description='test lambda function',
            Timeout=3,
            MemorySize=128,
            Publish=True,
            Code={
                'ZipFile': self._make_lambda_package()
            }
        )

    def _setup_dispatch(self):
        """Helper for setting up LambdaOutput dispatch"""
        self._create_lambda_function()
        return _get_alert(0)['default']

    @mock_lambda
    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """LambdaOutput dispatch"""
        alert = self._setup_dispatch()
        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('successfully sent alert to %s', self.__service)

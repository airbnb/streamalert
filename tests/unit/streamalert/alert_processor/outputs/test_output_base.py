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
import collections
# pylint: disable=abstract-class-instantiated,protected-access,attribute-defined-outside-init
from unittest.mock import MagicMock, Mock, patch

from moto import mock_kms, mock_ssm
from requests.exceptions import Timeout as ReqTimeout

from streamalert.alert_processor.outputs.aws import S3Output
from streamalert.alert_processor.outputs.output_base import (
    OutputDispatcher, OutputProperty, OutputRequestFailure, StreamAlertOutput)
from tests.unit.streamalert.alert_processor import (CONFIG, KMS_ALIAS,
                                                    MOCK_ENV, PREFIX, REGION)
from tests.unit.streamalert.alert_processor.helpers import \
    put_mock_ssm_parameters


def test_output_property_default():
    """OutputProperty defaults"""
    prop = OutputProperty()

    assert prop.description == ''
    assert prop.value == ''
    assert prop.input_restrictions == {' ', ':'}
    assert prop.mask_input == False
    assert prop.cred_requirement == False


def test_get_dispatcher_good():
    """StreamAlertOutput - Get Valid Dispatcher"""
    dispatcher = StreamAlertOutput.get_dispatcher('aws-s3')
    assert dispatcher is not None


@patch('logging.Logger.error')
def test_get_dispatcher_bad(log_mock):
    """StreamAlertOutput - Get Invalid Dispatcher"""
    dispatcher = StreamAlertOutput.get_dispatcher('aws-s4')
    assert dispatcher is None
    log_mock.assert_called_with('Designated output service [%s] does not exist', 'aws-s4')


@patch.dict('os.environ', MOCK_ENV)
def test_create_dispatcher():
    """StreamAlertOutput - Create Dispatcher"""
    dispatcher = StreamAlertOutput.create_dispatcher('aws-s3', CONFIG)
    assert isinstance(dispatcher, S3Output)


def test_user_defined_properties():
    """OutputDispatcher - User Defined Properties"""
    for output in list(StreamAlertOutput.get_all_outputs().values()):
        props = output.get_user_defined_properties()
        # The user defined properties should at a minimum contain a descriptor
        assert props.get('descriptor') is not None


def test_output_loading():
    """OutputDispatcher - Loading Output Classes"""
    loaded_outputs = set(StreamAlertOutput.get_all_outputs())
    # Add new outputs to this list to make sure they're loaded properly
    expected_outputs = {
        'aws-firehose',
        'aws-lambda',
        'aws-lambda-v2',
        'aws-s3',
        'aws-ses',
        'aws-sns',
        'aws-sqs',
        'aws-cloudwatch-log',
        'carbonblack',
        'demisto',
        'github',
        'jira',
        'jira-v2',
        'komand',
        'pagerduty',
        'pagerduty-v2',
        'pagerduty-incident',
        'phantom',
        'slack',
        'teams',
        'victorops'
    }
    assert collections.Counter(loaded_outputs) == collections.Counter(expected_outputs)


@patch.object(OutputDispatcher, '__service__', 'test_service')
class TestOutputDispatcher:
    """Test class for OutputDispatcher"""

    @patch.object(OutputDispatcher, '__service__', 'test_service')
    @patch.object(OutputDispatcher, '__abstractmethods__', frozenset())
    @patch.dict('os.environ', MOCK_ENV)
    def setup(self):
        """Setup before each method"""
        self._dispatcher = OutputDispatcher(CONFIG)
        self._descriptor = 'desc_test'

    @patch.object(OutputDispatcher, '__service__', 'test_service')
    @patch.object(OutputDispatcher, '__abstractmethods__', frozenset())
    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def test_credentials_provider(self, provider_constructor):
        """OutputDispatcher - Constructor"""
        provider = MagicMock()
        provider_constructor.return_value = provider

        _ = OutputDispatcher(CONFIG)

        provider_constructor.assert_called_with('test_service',
                                                config=CONFIG, defaults=None, region=REGION)
        assert self._dispatcher._credentials_provider._service_name == 'test_service'

    @patch('logging.Logger.info')
    def test_log_status_success(self, log_mock):
        """OutputDispatcher - Log status success"""
        self._dispatcher._log_status(True, self._descriptor)
        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    'test_service', self._descriptor)

    @patch('logging.Logger.error')
    def test_log_status_failed(self, log_mock):
        """OutputDispatcher - Log status failed"""
        self._dispatcher._log_status(False, self._descriptor)
        log_mock.assert_called_with('Failed to send alert to %s:%s',
                                    'test_service', self._descriptor)

    @patch('requests.Response')
    def test_check_http_response(self, mock_response):
        """OutputDispatcher - Check HTTP Response"""
        # Test with a good response code
        mock_response.status_code = 200
        result = self._dispatcher._check_http_response(mock_response)
        assert result

        # Test with a bad response code
        mock_response.status_code = 440
        result = self._dispatcher._check_http_response(mock_response)
        assert result == False

    @mock_ssm
    @mock_kms
    def test_load_creds(self):
        """OutputDispatcher - Load Credentials"""
        param_name = f'/{PREFIX}/streamalert/outputs/test_service/desc_test'
        creds = {
            'url': 'http://www.foo.bar/test',
            'token': 'token_to_encrypt'
        }

        put_mock_ssm_parameters(param_name, creds, KMS_ALIAS, region=REGION)

        loaded_creds = self._dispatcher._load_creds(self._descriptor)

        assert loaded_creds is not None
        assert len(loaded_creds) == 2
        assert loaded_creds['url'] == creds['url']
        assert loaded_creds['token'] == creds['token']

    def test_format_output_config(self):
        """OutputDispatcher - Format Output Config"""
        with patch.object(OutputDispatcher, '__service__', 'slack'):
            props = {'descriptor': OutputProperty('test_desc', 'test_channel')}

            formatted = self._dispatcher.format_output_config(CONFIG, props)

            assert len(formatted) == 2
            assert formatted[0] == 'unit_test_channel'
            assert formatted[1] == 'test_channel'

    @patch.object(OutputDispatcher, '_get_exceptions_to_catch', Mock(return_value=(ValueError)))
    def test_catch_exceptions_non_default(self):
        """OutputDispatcher - Catch Non Default Exceptions"""
        exceptions = self._dispatcher._catch_exceptions()

        assert exceptions == (OutputRequestFailure, ReqTimeout, ValueError)

    @patch.object(OutputDispatcher,
                  '_get_exceptions_to_catch', Mock(return_value=(ValueError, TypeError)))
    def test_catch_exceptions_non_default_tuple(self):
        """OutputDispatcher - Catch Non Default Exceptions Tuple"""
        exceptions = self._dispatcher._catch_exceptions()

        assert exceptions == (OutputRequestFailure, ReqTimeout, ValueError, TypeError)

    @patch.object(OutputDispatcher, '_get_exceptions_to_catch', Mock(return_value=()))
    def test_catch_exceptions_default(self):
        """OutputDispatcher - Catch Default Exceptions"""
        exceptions = self._dispatcher._catch_exceptions()

        assert exceptions == (OutputRequestFailure, ReqTimeout)

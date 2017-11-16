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
# pylint: disable=abstract-class-instantiated,protected-access,no-self-use
from mock import patch, Mock
from nose.tools import (
    assert_equal,
    raises
)

from stream_alert.threat_intel_downloader.threat_stream import ThreatStream
from stream_alert.threat_intel_downloader.main import (
    handler,
    invoke_lambda_function,
    parse_config
)

from stream_alert.threat_intel_downloader.exceptions import ThreatStreamLambdaInvokeError

from tests.unit.threat_intel_downloader.test_helpers import (
    get_mock_context,
    mock_requests_get,
    MockSSMClient
)

from tests.unit.app_integrations.test_helpers import MockLambdaClient

@patch('boto3.client', Mock(return_value=MockSSMClient(valid_creds=1)))
@patch.object(ThreatStream, '_connect')
def test_handler_without_next_token(mock_threatstream_connect):
    """Threat Intel Downloader - Test handler"""
    handler(None, get_mock_context())
    mock_threatstream_connect.assert_not_called()

@patch('boto3.client', Mock(return_value=MockSSMClient(valid_creds=1)))
@patch('stream_alert.threat_intel_downloader.threat_stream.requests.get',
       side_effect=mock_requests_get)
def test_handler_next_token(mock_get):
    """Threat Intel Downloader - Test handler with next token passed in"""
    handler({'next_url': 'next_token'}, get_mock_context())
    mock_get.assert_called()

@patch('boto3.client', Mock(return_value=MockLambdaClient()))
def test_invoke_lambda_function():
    """Threat Intel Downloader - Test invoke_lambda_function"""
    config = {
        'region': 'us-east-1',
        'account_id': '123456789012',
        'function_name': 'prefix_threat_intel_downloader',
        'qualifier': 'development'
    }
    invoke_lambda_function('next_token', config)

@patch('boto3.client', Mock(return_value=MockLambdaClient()))
@raises(ThreatStreamLambdaInvokeError)
def test_invoke_lambda_function_error():
    """Threat Intel Downloader - Test invoke_lambda_function with error"""
    MockLambdaClient._raise_exception = True
    config = {
        'region': 'us-east-1',
        'account_id': '123456789012',
        'function_name': 'prefix_threat_intel_downloader',
        'qualifier': 'development'
    }
    invoke_lambda_function('next_token', config)

def test_parse_config():
    """Threat Intel Downloader - Test parse_config"""
    expect_config = {
        'region': 'us-east-1',
        'account_id': '123456789012',
        'function_name': 'prefix_threat_intel_downloader',
        'qualifier': 'development'
    }
    assert_equal(parse_config(get_mock_context()), expect_config)

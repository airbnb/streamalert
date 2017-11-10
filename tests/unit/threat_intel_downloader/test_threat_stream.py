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
from mock import patch, Mock, call
from nose.tools import (
    assert_equal,
    assert_false,
    assert_is_not_none,
    assert_true,
    raises
)

import boto3

from stream_alert.threat_intel_downloader.exceptions import ThreatStreamCredsError
from stream_alert.threat_intel_downloader.threat_stream import ThreatStream

from tests.unit.threat_intel_downloader.test_helpers import (
    mock_requests_get,
    MockSSMClient
)

class TestThreatStream(object):
    """Test class to test ThreatStream functionalities"""
    def __init__(self):
        self.threatstream = None
        self.ioc_types = set(['domain'])
        self.region = 'us-east-1'
        self.table_name = 'test_table_name'

    @patch('boto3.client', Mock(return_value=MockSSMClient(valid_creds=2)))
    @patch('stream_alert.threat_intel_downloader.threat_stream.requests.get',
           side_effect=mock_requests_get)
    def test_runner(self, mock_get): # pylint: disable=unused-argument
        """ThreatStream - Test connection to threatstream"""
        threat_stream = ThreatStream(self.ioc_types, self.region)
        threat_stream.ioc_sources = set(['ioc_source'])
        intelligence, next_url, continue_invoke = threat_stream.runner(None)
        assert_equal(intelligence, None)
        assert_equal(next_url, None)
        assert_equal(continue_invoke, False)

        intelligence, next_url, continue_invoke = threat_stream.runner({'foo': 'bar'})
        assert_true(isinstance(intelligence, list))
        assert_equal(len(intelligence), 1)
        assert_is_not_none(next_url)
        assert_equal(continue_invoke, False)

        intelligence, next_url, continue_invoke = threat_stream.runner({'next_url': 'next_url'})
        assert_true(isinstance(intelligence, list))
        assert_equal(len(intelligence), 1)
        assert_equal(next_url, 'next_url')
        assert_equal(continue_invoke, False)

    @patch('boto3.client', Mock(return_value=MockSSMClient(valid_creds=2)))
    def test_process_data(self):
        """ThreatStream - Test raw ioc data is processed correctly"""
        raw_data = [
            {
                'value': 'malicious_domain.com',
                'itype': 'c2_domain',
                'source': 'ioc_source',
                'type': 'domain'
            },
            {
                'value': 'malicious_domain2.com',
                'itype': 'c2_domain',
                'source': 'ioc_source2',
                'type': 'domain'
            }
        ]
        threat_stream = ThreatStream(self.ioc_types, self.region)
        threat_stream.ioc_sources = set(['ioc_source'])
        processed_data = threat_stream._process_data(raw_data)
        assert_equal(len(processed_data), 2)
        assert_equal(processed_data[0],
                     ['malicious_domain.com', 'domain', 'c2_domain', 'ioc_source'])
        assert_equal(processed_data[1],
                     ['malicious_domain2.com', 'domain', 'c2_domain', 'ioc_source2'])

    @patch('boto3.client', Mock(return_value=MockSSMClient(valid_creds=2)))
    def test_get_api_creds(self):
        """ThreatStream - Test get api creds from SSM"""
        threat_stream = ThreatStream(self.ioc_types, self.region)
        assert_equal(threat_stream.api_user, 'test_api_user')
        assert_equal(threat_stream.api_key, 'test_api_key')

    @patch('boto3.client')
    @raises(ThreatStreamCredsError)
    def test_get_api_creds_errors(self, mock_boto3_client):
        """ThreatStream - Test get api creds from SSM"""
        mock_boto3_client.return_value = MockSSMClient(valid_creds=1)
        ThreatStream(self.ioc_types, self.region)

        mock_boto3_client.return_value = MockSSMClient(valid_creds=0)
        ThreatStream(self.ioc_types, self.region)

    # TODO: add more test cases with different status_code
    @patch('boto3.client', Mock(return_value=MockSSMClient(valid_creds=2)))
    @patch('stream_alert.threat_intel_downloader.threat_stream.requests.get',
           side_effect=mock_requests_get)
    def test_connect(self, mock_get): # pylint: disable=unused-argument
        """ThreatStream - Test connection to ThreatStream.com"""
        threat_stream = ThreatStream(self.ioc_types, self.region)
        threat_stream.ioc_sources = set(['test_source'])
        intelligence, next_url, continue_invoke = threat_stream._connect('next_token')
        expected_intel = [['malicious_domain2.com', 'domain', 'c2_domain', 'test_source']]
        assert_equal(intelligence, expected_intel)
        assert_equal(next_url, 'next_token')
        assert_false(continue_invoke)

    @patch('boto3.client', Mock(return_value=MockSSMClient(valid_creds=2)))
    @patch.object(boto3, 'resource')
    @patch('stream_alert.threat_intel_downloader.threat_stream.requests.get',
           side_effect=mock_requests_get)
    def test_write_to_dynamodb_table(self, mock_get, mock_boto3_resource): # pylint: disable=unused-argument
        """ThreatStream - Test write action to dynamodb table"""
        threat_stream = ThreatStream(self.ioc_types, self.region)
        threat_stream.ioc_sources = set(['test_source'])
        intelligence, _, _ = threat_stream.runner({'next_url': 'next_url'})
        threat_stream.write_to_dynamodb_table(intelligence)
        calls = [
            call('dynamodb', region_name='us-east-1'),
            call().Table('test_table_name'),
            call().Table().batch_writer(),
            call().Table().batch_writer().__enter__(),
            call().Table().batch_writer().__enter__().put_item(
                Item={
                    'source': 'test_source',
                    'type': 'domain',
                    'sub_type': 'c2_domain',
                    'value': 'malicious_domain2.com'
                }
            ),
            call().Table().batch_writer().__exit__(None, None, None)
        ]
        mock_boto3_resource.assert_has_calls(calls)

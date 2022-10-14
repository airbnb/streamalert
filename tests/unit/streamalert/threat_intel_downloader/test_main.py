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
import os
from datetime import datetime
from unittest.mock import Mock, patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_ssm

from streamalert.shared.config import load_config
from streamalert.threat_intel_downloader.exceptions import (
    ThreatStreamCredsError, ThreatStreamLambdaInvokeError,
    ThreatStreamRequestsError)
from streamalert.threat_intel_downloader.main import ThreatStream
from tests.unit.streamalert.apps.test_helpers import MockLambdaClient
from tests.unit.streamalert.shared.test_config import get_mock_lambda_context
from tests.unit.streamalert.threat_intel_downloader.test_helpers import \
    put_mock_params


@patch('time.sleep', Mock())
class TestThreatStream:
    """Test class to test ThreatStream functionalities"""
    # pylint: disable=protected-access

    @patch('streamalert.threat_intel_downloader.main.load_config',
           Mock(return_value=load_config('tests/unit/conf/')))
    def setup(self):
        """Setup TestThreatStream"""
        # pylint: disable=attribute-defined-outside-init
        context = get_mock_lambda_context('prefix_threat_intel_downloader', 100000)
        self.threatstream = ThreatStream(
            context.invoked_function_arn,
            context.get_remaining_time_in_millis
        )

    @staticmethod
    def _get_fake_intel(value, source):
        return {
            'value': value,
            'itype': 'c2_domain',
            'source': source,
            'type': 'domain',
            'expiration_ts': '2017-11-30T00:01:02.123Z',
            'key1': 'value1',
            'key2': 'value2'
        }

    @staticmethod
    def _get_http_response(next_url=None):
        return {
            'key1': 'value1',
            'objects': [
                TestThreatStream._get_fake_intel('malicious_domain.com', 'ioc_source'),
                TestThreatStream._get_fake_intel('malicious_domain2.com', 'test_source')
            ],
            'meta': {
                'next': next_url,
                'offset': 100
            }
        }

    @patch('streamalert.threat_intel_downloader.main.load_config',
           Mock(return_value=load_config('tests/unit/conf/')))
    def test_load_config(self):
        """ThreatStream - Load Config"""
        arn = 'arn:aws:lambda:region:123456789012:function:name:development'
        expected_config = {
            'account_id': '123456789012',
            'function_name': 'name',
            'qualifier': 'development',
            'region': 'region',
            'enabled': True,
            'excluded_sub_types': [
                'bot_ip',
                'brute_ip',
                'scan_ip',
                'spam_ip',
                'tor_ip'
            ],
            'ioc_filters': [
                'crowdstrike',
                '@airbnb.com'
            ],
            'ioc_keys': [
                'expiration_ts',
                'itype',
                'source',
                'type',
                'value'
            ],
            'ioc_types': [
                'domain',
                'ip',
                'md5'
            ],
            'memory': '128',
            'timeout': '60'
        }
        assert self.threatstream._load_config(arn) == expected_config

    def test_process_data(self):
        """ThreatStream - Process Raw IOC Data"""
        raw_data = [
            self._get_fake_intel('malicious_domain.com', 'ioc_source'),
            self._get_fake_intel('malicious_domain2.com', 'ioc_source2'),
            # this will get filtered out
            self._get_fake_intel('malicious_domain3.com', 'bad_source_ioc'),
        ]
        self.threatstream._config['ioc_filters'] = {'ioc_source'}
        processed_data = self.threatstream._process_data(raw_data)
        expected_result = [
            {
                'value': 'malicious_domain.com',
                'itype': 'c2_domain',
                'source': 'ioc_source',
                'type': 'domain',
                'expiration_ts': 1512000062
            },
            {
                'value': 'malicious_domain2.com',
                'itype': 'c2_domain',
                'source': 'ioc_source2',
                'type': 'domain',
                'expiration_ts': 1512000062
            }
        ]
        assert processed_data == expected_result

    @mock_ssm
    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def test_load_api_creds(self):
        """ThreatStream - Load API creds from SSM"""
        value = {'api_user': 'test_user', 'api_key': 'test_key'}
        put_mock_params(ThreatStream.CRED_PARAMETER_NAME, value)
        self.threatstream._load_api_creds()
        assert self.threatstream.api_user == 'test_user'
        assert self.threatstream.api_key == 'test_key'

    @mock_ssm
    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def test_load_api_creds_cached(self):
        """ThreatStream - Load API creds from SSM, Cached"""
        value = {'api_user': 'test_user', 'api_key': 'test_key'}
        put_mock_params(ThreatStream.CRED_PARAMETER_NAME, value)
        self.threatstream._load_api_creds()
        assert self.threatstream.api_user == 'test_user'
        assert self.threatstream.api_key == 'test_key'
        self.threatstream._load_api_creds()

    @mock_ssm
    @pytest.mark.xfail(raises=ClientError)
    def test_load_api_creds_client_errors(self):
        """ThreatStream - Load API creds from SSM, ClientError"""
        self.threatstream._load_api_creds()

    @patch('boto3.client')
    @pytest.mark.xfail(raises=ThreatStreamCredsError)
    def test_load_api_creds_empty_response(self, boto_mock):
        """ThreatStream - Load API creds from SSM, Empty Response"""
        boto_mock.return_value.get_parameter.return_value = None
        self.threatstream._load_api_creds()

    @mock_ssm
    @pytest.mark.xfail(raises=ThreatStreamCredsError)
    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def test_load_api_creds_invalid_json(self):
        """ThreatStream - Load API creds from SSM with invalid JSON"""
        boto3.client('ssm').put_parameter(
            Name=ThreatStream.CRED_PARAMETER_NAME,
            Value='invalid_value',
            Type='SecureString',
            Overwrite=True
        )
        self.threatstream._load_api_creds()

    @mock_ssm
    @pytest.mark.xfail(raises=ThreatStreamCredsError)
    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def test_load_api_creds_no_api_key(self):
        """ThreatStream - Load API creds from SSM, No API Key"""
        value = {'api_user': 'test_user', 'api_key': ''}
        put_mock_params(ThreatStream.CRED_PARAMETER_NAME, value)
        self.threatstream._load_api_creds()

    @patch('streamalert.threat_intel_downloader.main.datetime')
    def test_epoch_now(self, date_mock):
        """ThreatStream - Epoch, Now"""
        fake_date_now = datetime(year=2017, month=9, day=1)
        date_mock.utcnow.return_value = fake_date_now
        date_mock.utcfromtimestamp = datetime.utcfromtimestamp
        expected_value = datetime(year=2017, month=11, day=30)
        value = self.threatstream._epoch_time(None)
        assert datetime.utcfromtimestamp(value) == expected_value

    def test_epoch_from_time(self):
        """ThreatStream - Epoch, From Timestamp"""
        expected_value = datetime(year=2017, month=11, day=30)
        value = self.threatstream._epoch_time('2017-11-30T00:00:00.000Z')
        assert datetime.utcfromtimestamp(value) == expected_value

    @pytest.mark.xfail(raises=ValueError)
    def test_epoch_from_bad_time(self):
        """ThreatStream - Epoch, Error"""
        self.threatstream._epoch_time('20171130T00:00:00.000Z')

    def test_excluded_sub_types(self):
        """ThreatStream - Excluded Sub Types Property"""
        expected_value = ['bot_ip', 'brute_ip', 'scan_ip', 'spam_ip', 'tor_ip']
        assert self.threatstream.excluded_sub_types == expected_value

    def test_ioc_keys(self):
        """ThreatStream - IOC Keys Property"""
        expected_value = ['expiration_ts', 'itype', 'source', 'type', 'value']
        assert self.threatstream.ioc_keys == expected_value

    def test_ioc_sources(self):
        """ThreatStream - IOC Sources Property"""
        expected_value = ['crowdstrike', '@airbnb.com']
        assert self.threatstream.ioc_sources == expected_value

    def test_ioc_types(self):
        """ThreatStream - IOC Types Property"""
        expected_value = ['domain', 'ip', 'md5']
        assert self.threatstream.ioc_types == expected_value

    def test_threshold(self):
        """ThreatStream - Threshold Property"""
        assert self.threatstream.threshold == 499000

    @patch('streamalert.threat_intel_downloader.main.ThreatStream._finalize')
    @patch('streamalert.threat_intel_downloader.main.requests.get')
    def test_connect(self, get_mock, finalize_mock):
        """ThreatStream - Connection to ThreatStream.com"""
        get_mock.return_value.json.return_value = self._get_http_response()
        get_mock.return_value.status_code = 200
        self.threatstream._config['ioc_filters'] = {'test_source'}
        self.threatstream._connect('previous_url')
        expected_intel = [
            {
                'value': 'malicious_domain2.com',
                'itype': 'c2_domain',
                'source': 'test_source',
                'type': 'domain',
                'expiration_ts': 1512000062
            }
        ]
        finalize_mock.assert_called_with(expected_intel, None)

    @patch('streamalert.threat_intel_downloader.main.ThreatStream._finalize')
    @patch('streamalert.threat_intel_downloader.main.requests.get')
    def test_connect_with_next(self, get_mock, finalize_mock):
        """ThreatStream - Connection to ThreatStream.com, with Continuation"""
        next_url = 'this_url'
        get_mock.return_value.json.return_value = self._get_http_response(next_url)
        get_mock.return_value.status_code = 200
        self.threatstream._config['ioc_filters'] = {'test_source'}
        self.threatstream._connect('previous_url')
        expected_intel = [
            {
                'value': 'malicious_domain2.com',
                'itype': 'c2_domain',
                'source': 'test_source',
                'type': 'domain',
                'expiration_ts': 1512000062
            }
        ]
        finalize_mock.assert_called_with(expected_intel, next_url)

    @pytest.mark.xfail(raises=ThreatStreamRequestsError)
    @patch('streamalert.threat_intel_downloader.main.requests.get')
    def test_connect_with_unauthed(self, get_mock):
        """ThreatStream - Connection to ThreatStream.com, Unauthorized Error"""
        get_mock.return_value.json.return_value = self._get_http_response()
        get_mock.return_value.status_code = 401
        self.threatstream._connect('previous_url')

    @pytest.mark.xfail(raises=ThreatStreamRequestsError)
    @patch('streamalert.threat_intel_downloader.main.requests.get')
    def test_connect_with_retry_error(self, get_mock):
        """ThreatStream - Connection to ThreatStream.com, Retry Error"""
        get_mock.return_value.status_code = 500
        self.threatstream._connect('previous_url')

    @pytest.mark.xfail(raises=ThreatStreamRequestsError)
    @patch('streamalert.threat_intel_downloader.main.requests.get')
    def test_connect_with_unknown_error(self, get_mock):
        """ThreatStream - Connection to ThreatStream.com, Unknown Error"""
        get_mock.return_value.status_code = 404
        self.threatstream._connect('previous_url')

    @patch('streamalert.threat_intel_downloader.main.ThreatStream._load_api_creds')
    @patch('streamalert.threat_intel_downloader.main.ThreatStream._connect')
    def test_runner(self, connect_mock, _):
        """ThreatStream - Runner"""
        expected_url = ('/api/v2/intelligence/?username=user&api_key=key&limit=1000&q='
                        '(status="active")+AND+(type="domain"+OR+type="ip"+OR+type="md5")+'
                        'AND+NOT+(itype="bot_ip"+OR+itype="brute_ip"+OR+itype="scan_ip"+'
                        'OR+itype="spam_ip"+OR+itype="tor_ip")')
        self.threatstream.api_key = 'key'
        self.threatstream.api_user = 'user'
        self.threatstream.runner({'none': 'test'})
        connect_mock.assert_called_with(expected_url)

    @patch('streamalert.threat_intel_downloader.main.ThreatStream._write_to_dynamodb_table')
    @patch('streamalert.threat_intel_downloader.main.ThreatStream._invoke_lambda_function')
    def test_finalize(self, invoke_mock, write_mock):
        """ThreatStream - Finalize with Intel"""
        intel = ['foo', 'bar']
        self.threatstream._finalize(intel, None)
        write_mock.assert_called_with(intel)
        invoke_mock.assert_not_called()

    @patch('streamalert.threat_intel_downloader.main.ThreatStream._write_to_dynamodb_table')
    @patch('streamalert.threat_intel_downloader.main.ThreatStream._invoke_lambda_function')
    def test_finalize_next_url(self, invoke_mock, write_mock):
        """ThreatStream - Finalize with Next URL"""
        intel = ['foo', 'bar']
        self.threatstream._finalize(intel, 'next')
        write_mock.assert_called_with(intel)
        invoke_mock.assert_called_with('next')

    @patch('boto3.resource')
    def test_write_to_dynamodb_table(self, boto_mock):
        """ThreatStream - Write Intel to DynamoDB Table"""
        intel = [self._get_fake_intel('malicious_domain.com', 'test_source')]
        expected_intel = {
            'expiration_ts': '2017-11-30T00:01:02.123Z',
            'source': 'test_source',
            'ioc_type': 'domain',
            'sub_type': 'c2_domain',
            'ioc_value': 'malicious_domain.com'
        }
        self.threatstream._write_to_dynamodb_table(intel)
        batch_writer = boto_mock.return_value.Table.return_value.batch_writer.return_value
        batch_writer.__enter__.return_value.put_item.assert_called_with(Item=expected_intel)

    @patch('boto3.resource')
    @pytest.mark.xfail(raises=ClientError)
    def test_write_to_dynamodb_table_error(self, boto_mock):
        """ThreatStream - Write Intel to DynamoDB Table, Error"""
        intel = [self._get_fake_intel('malicious_domain.com', 'test_source')]
        err = ClientError({'Error': {'Code': 404}}, 'PutItem')
        batch_writer = boto_mock.return_value.Table.return_value.batch_writer.return_value
        batch_writer.__enter__.return_value.put_item.side_effect = err

        self.threatstream._write_to_dynamodb_table(intel)

    @patch('boto3.client')
    def test_invoke_lambda_function(self, boto_mock):
        """ThreatStream - Invoke Lambda Function"""
        boto_mock.return_value = MockLambdaClient()
        self.threatstream._invoke_lambda_function('next_token')
        boto_mock.assert_called_once()

    @patch('boto3.client', Mock(return_value=MockLambdaClient()))
    @pytest.mark.xfail(raises=ThreatStreamLambdaInvokeError)
    def test_invoke_lambda_function_error(self):
        """ThreatStream - Invoke Lambda Function, Error"""
        MockLambdaClient._raise_exception = True
        self.threatstream._invoke_lambda_function('next_token')

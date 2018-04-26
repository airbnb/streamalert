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
import boto3
from botocore.exceptions import ClientError
from mock import patch
from moto import mock_kms, mock_s3
from nose.tools import assert_true, raises

from stream_alert.alert_processor.outputs.output_base import OutputProperty
from stream_alert_cli.outputs import encrypt_and_push_creds_to_s3


@patch('stream_alert_cli.outputs.encrypt_and_push_creds_to_s3')
@mock_kms
@mock_s3
def test_encrypt_and_push_creds_to_s3(cli_mock):
    """CLI - Outputs - Encrypt and push creds to s3"""
    props = {
        'non-secret': OutputProperty(
            description='short description of info needed',
            value='http://this.url.value')}

    return_value = encrypt_and_push_creds_to_s3('us-east-1', 'bucket', 'key', props, 'test_alias')

    assert_true(return_value)
    cli_mock.assert_not_called()

    props['secret'] = OutputProperty(
        description='short description of secret needed',
        value='1908AGSG98A8908AG',
        cred_requirement=True)

    # Create the bucket to hold the mock object being put
    boto3.client('s3', region_name='us-east-1').create_bucket(Bucket='bucket')

    return_value = encrypt_and_push_creds_to_s3('us-east-1', 'bucket', 'key', props, 'test_alias')

    assert_true(return_value)


@raises(ClientError)
@patch('boto3.client')
@patch('logging.Logger.error')
def test_encrypt_and_push_creds_to_s3_kms_failure(log_mock, boto_mock):
    """CLI - Outputs - Encrypt and push creds to s3 - kms failure"""
    props = {
        'secret': OutputProperty(
            description='short description of secret needed',
            value='1908AGSG98A8908AG',
            cred_requirement=True)}

    err_response = {
        'Error':
            {
                'Code': 100,
                'Message': 'BAAAD',
                'BucketName': 'bucket'
            }
    }

    # Add ClientError side_effect to mock
    boto_mock.side_effect = ClientError(err_response, 'operation')
    encrypt_and_push_creds_to_s3('us-east-1', 'bucket', 'key', props, 'test_alias')

    log_mock.assert_called_with('An error occurred during credential encryption')

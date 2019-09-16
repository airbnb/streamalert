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
import tempfile

from botocore.exceptions import ClientError
from mock import patch
from moto import mock_kms, mock_s3
from nose.tools import assert_equal, raises

from streamalert.shared.helpers.aws_api_client import AwsS3, AwsKms
from tests.unit.helpers.aws_mocks import put_mock_s3_object
from tests.unit.streamalert.alert_processor. import KMS_ALIAS, REGION


class TestAwsKms:

    @staticmethod
    @mock_kms
    def test_encrypt_decrypt():
        """AwsApiClient - AwsKms - encrypt/decrypt - Encrypt and push creds, then pull them down"""
        secret = 'shhhhhh'.encode() # nosec

        ciphertext = AwsKms.encrypt(secret, region=REGION, key_alias=KMS_ALIAS)
        response = AwsKms.decrypt(ciphertext, region=REGION)

        assert_equal(response, secret)

    @staticmethod
    @raises(ClientError)
    @patch('boto3.client')
    def test_encrypt_kms_failure(boto_mock):
        """AwsApiClient - AwsKms - Encrypt - KMS Failure"""
        response = {
            'Error': {
                'ErrorCode': 400,
                'Message': "bad bucket"
            }
        }
        boto_mock.side_effect = ClientError(response, 'operation')
        AwsKms.encrypt('secret', region=REGION, key_alias=KMS_ALIAS)


class TestAwsS3:

    @staticmethod
    @mock_s3
    def test_put_download():
        """AwsApiClient - AwsS3 - PutObject/Download - Upload then download object"""
        payload = 'zzzzz'.encode()
        bucket = 'bucket'
        key = 'key'

        # Annoyingly, moto needs us to create the bucket first
        # We put a random unrelated object into the bucket and this will set up the bucket for us
        put_mock_s3_object(bucket, 'aaa', 'bbb', REGION)

        AwsS3.put_object(payload, bucket=bucket, key=key, region=REGION)

        with tempfile.SpooledTemporaryFile(0, 'a+b') as file_handle:
            result = AwsS3.download_fileobj(file_handle, bucket=bucket, key=key, region=REGION)

        assert_equal(result, payload)

    @staticmethod
    @raises(ClientError)
    @mock_s3
    def test_put_object_s3_failure():
        """AwsApiClient - AwsS3 - PutObject - S3 Failure"""

        # S3 will automatically fail because the bucket has not been created yet.
        AwsS3.put_object('zzzpayload', bucket='aaa', key='zzz', region=REGION)

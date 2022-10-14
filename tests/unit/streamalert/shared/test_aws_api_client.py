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
from unittest.mock import patch

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_kms

from streamalert.shared.helpers.aws_api_client import AwsKms
from tests.unit.streamalert.alert_processor import KMS_ALIAS, REGION


class TestAwsKms:

    @staticmethod
    @mock_kms
    def test_encrypt_decrypt():
        """AwsApiClient - AwsKms - encrypt/decrypt - Encrypt and push creds, then pull them down"""
        secret = b'shhhhhh'  # nosec

        client = boto3.client('kms', region_name=REGION)
        response = client.create_key()
        client.create_alias(
            AliasName=KMS_ALIAS,
            TargetKeyId=response['KeyMetadata']['KeyId']
        )

        ciphertext = AwsKms.encrypt(secret, region=REGION, key_alias=KMS_ALIAS)
        response = AwsKms.decrypt(ciphertext, region=REGION)

        assert response == secret

    @staticmethod
    @pytest.mark.xfail(raises=ClientError)
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

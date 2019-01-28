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
import json
import boto3

from botocore.exceptions import ClientError

from stream_alert.shared.logger import get_logger
from stream_alert.shared.helpers.boto import default_config

LOGGER = get_logger(__name__)


class AwsKms(object):
    @staticmethod
    def encrypt(plaintext_data, region, key_alias):
        """Encrypts the given plaintext data using AWS KMS

        Args:
            plaintext_data (str): The raw, unencrypted data to be encrypted
            region (str): AWS region
            key_alias (str): KMS Key Alias

        Returns:
            string: The encrypted ciphertext

        Raises:
            ClientError
        """
        try:
            key_id = 'alias/{}'.format(key_alias)
            client = boto3.client('kms', config=default_config(region=region))
            response = client.encrypt(KeyId=key_id, Plaintext=plaintext_data)
            return response['CiphertextBlob']
        except ClientError:
            LOGGER.error('An error occurred during KMS encryption')
            raise

    @staticmethod
    def decrypt(ciphertext, region):
        """Decrypts the given ciphertext using AWS KMS

        Args:
            ciphertext (str): The raw, encrypted data to be decrypted
            region (str): AWS region

        Return:
            string: The decrypted plaintext

        Raises:
            ClientError
        """
        try:
            client = boto3.client('kms', config=default_config(region=region))
            response = client.decrypt(CiphertextBlob=ciphertext)
            return response['Plaintext']
        except ClientError:
            LOGGER.error('An error occurred during KMS decryption')
            raise


class AwsS3(object):
    @staticmethod
    def put_object(object_data, bucket, key, region):
        """Saves the given data into AWS S3

        Args:
            object_data (str): The raw object data to save
            region (str): AWS region
            bucket (str): AWS S3 bucket name
            key (str): AWS S3 key name

        Returns:
            bool: True on success

        Raises:
            ClientError
        """
        try:
            client = boto3.client('s3', config=default_config(region=region))
            client.put_object(Body=object_data, Bucket=bucket, Key=key)
            return True
        except ClientError:
            LOGGER.error('An error occurred during S3 PutObject')
            raise

    @staticmethod
    def download_fileobj(file_handle, bucket, key, region):
        """Downloads the requested S3 object and saves it into the given file handle.

        This method also returns the downloaded payload.

        Args:
            file_handle (File): A File-like object to save the downloaded contents
            region (str): AWS region
            bucket (str): AWS S3 bucket name
            key (str): AWS S3 key name

        Returns:
            str: The downloaded payload

        Raises:
            ClientError
        """
        try:
            client = boto3.client('s3', config=default_config(region=region))
            client.download_fileobj(
                bucket,
                key,
                file_handle
            )

            file_handle.seek(0)
            return file_handle.read()
        except ClientError:
            LOGGER.error('An error occurred during S3 DownloadFileobj')
            raise

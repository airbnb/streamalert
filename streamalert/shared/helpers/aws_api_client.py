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
import json

import boto3
from botocore.exceptions import ClientError

from streamalert.shared.helpers.boto import default_config
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


class AwsKms:
    @staticmethod
    def encrypt(plaintext_data, region, key_alias):
        """Encrypts the given plaintext data using AWS KMS

        See:
          https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html

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
            if not key_alias.startswith('alias/'):
                key_alias = f'alias/{key_alias}'
            client = boto3.client('kms', config=default_config(region=region))
            response = client.encrypt(KeyId=key_alias, Plaintext=plaintext_data)
            return response['CiphertextBlob']
        except ClientError:
            LOGGER.error('An error occurred during KMS encryption')
            raise

    @staticmethod
    def decrypt(ciphertext, region):
        """Decrypts the given ciphertext using AWS KMS

        See:
          https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html

        Args:
            ciphertext (str): The raw, encrypted data to be decrypted
            region (str): AWS region

        Returns:
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


class AwsS3:
    @staticmethod
    def head_bucket(bucket, region):
        """Determines if given bucket exists with correct permissions.

        See:
            https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketHEAD.html

        Args:
            bucket (str): AWS S3 bucket name
            region (str): AWS Region

        Returns:
            bool: True on success

        Raises:
            ClientError; Raises when the bucket does not exist or is denying permission to access.
        """
        try:
            client = boto3.client('s3', config=default_config(region=region))
            client.head_bucket(Bucket=bucket)
        except ClientError:
            LOGGER.error('An error occurred during S3 HeadBucket')
            raise

    @staticmethod
    def create_bucket(bucket, region):
        """Creates the given S3 bucket

        See:
            https://docs.aws.amazon.com/cli/latest/reference/s3api/create-bucket.html

        Args:
            bucket (str): The string name of the intended S3 bucket
            region (str): AWS Region

        Returns:
            bool: True on success

        Raises:
            ClientError
        """
        try:
            client = boto3.client('s3', config=default_config(region=region))
            client.create_bucket(Bucket=bucket)
            return True
        except ClientError:
            LOGGER.error('An error occurred during S3 CreateBucket')
            raise

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
            client.download_fileobj(bucket, key, file_handle)

            file_handle.seek(0)
            return file_handle.read()
        except ClientError:
            LOGGER.error('An error occurred during S3 DownloadFileobj')
            raise


class AwsSsm:
    """Class containing helper functions for aws ssm"""
    @staticmethod
    def get_parameter(parameter_name, region, with_decryption=True):
        """gets the parameter_name from SSM Parameter store

        Args:
            parameter_name (str): The name of the parameter to fetch
            region (str): AWS region
            with_decryption (bool): Should decryption be attempted via this call

        Returns:
            str: The parameter either encrypted or not

        Raises:
            ClientError
        """
        client = boto3.client('ssm', config=default_config(region=region))

        try:
            response = client.get_parameter(Name=parameter_name, WithDecryption=with_decryption)
        except ClientError:
            LOGGER.error('Error getting parameter %s', parameter_name)
            raise
        else:
            return response["Parameter"]["Value"]

    @staticmethod
    def put_parameter(name, value, region, kms_key_alias):
        """puts a parameter into SSM Parameter store

        Args:
            name (str): The name of the parameter to save
            value (str or dict): The value of the parameter to save
            region (str): AWS region
            kms_key_alias (str): The kms key alias in use for secrets

        Returns:
            bool: True if successful else False
        """
        client = boto3.client('ssm', config=default_config(region=region))
        result = False

        key_id = f'alias/{kms_key_alias}'
        parameter_value = json.dumps(value) if isinstance(value, dict) else str(value)
        try:
            client.put_parameter(Name=name,
                                 Description='StreamAlert Secret',
                                 Value=parameter_value,
                                 Type='SecureString',
                                 KeyId=key_id,
                                 Overwrite=True,
                                 Tier='Standard')
        except ClientError as err:
            LOGGER.exception('Error saving parameter %s to SSM Param Store\n%s', name, err)
            result = False
        else:
            result = True

        return result

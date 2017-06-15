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
import json
import os
import subprocess
import zipfile

from StringIO import StringIO

import boto3

from stream_alert_cli.logger import LOGGER_CLI


class CLIHelpers(object):
    """Common helpers between StreamAlert CLI classes"""
    @classmethod
    def run_command(cls, runner_args, **kwargs):
        """Helper function to run commands with error handling.

        Args:
            runner_args (list): Commands to run via subprocess
            kwargs:
                cwd (string): A path to execute commands from
                error_message (string): Message to show if command fails
                quiet (boolean): Whether to show command output or hide it

        """
        default_error_message = "An error occurred while running: {}".format(
            ' '.join(runner_args)
        )
        error_message = kwargs.get('error_message', default_error_message)

        default_cwd = 'terraform'
        cwd = kwargs.get('cwd', default_cwd)

        stdout_option = None
        if kwargs.get('quiet'):
            stdout_option = open(os.devnull, 'w')

        try:
            subprocess.check_call(runner_args, stdout=stdout_option, cwd=cwd)
        except subprocess.CalledProcessError as e:
            LOGGER_CLI.error('Return Code %s - %s', e.returncode, e.cmd)
            return False

        return True


def _create_lambda_function(function_name, region):
    """Helper function to create mock lambda function"""
    boto3.client('lambda', region_name=region).create_function(
        FunctionName=function_name,
        Runtime='python2.7',
        Role='test-iam-role',
        Handler='function.handler',
        Description='test lambda function',
        Timeout=3,
        MemorySize=128,
        Publish=True,
        Code={
            'ZipFile': _make_lambda_package()
        }
    )

def _encrypt_with_kms(data, region, alias):
    kms_client = boto3.client('kms', region_name=region)
    response = kms_client.encrypt(KeyId=alias,
                                  Plaintext=data)

    return response['CiphertextBlob']


def _make_lambda_package():
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


def _put_mock_creds(output_name, creds, bucket, region, alias):
    """Helper function to mock encrypt creds and put on s3"""
    creds_string = json.dumps(creds)

    enc_creds = _encrypt_with_kms(creds_string, region, alias)

    _put_mock_s3_object(bucket, output_name, enc_creds, region)


def _put_mock_s3_object(bucket, key, data, region):
    """Create a mock AWS S3 object for testing

    Args:
        bucket: the bucket in which to place the object (string)
        key: the key to use for the S3 object (string)
        data: the actual value to use for the object (string)
        region: the aws region to use for this boto3 client
    """
    s3_client = boto3.client('s3', region_name=region)
    s3_client.create_bucket(Bucket=bucket)
    s3_client.put_object(
        Body=data,
        Bucket=bucket,
        Key=key,
        ServerSideEncryption='AES256'
    )

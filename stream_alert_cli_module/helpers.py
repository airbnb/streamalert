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
import base64
import json
import os
import random
import subprocess
from StringIO import StringIO
import zipfile
import zlib

import boto3

from stream_alert_cli_module.logger import LOGGER_CLI


DIR_TEMPLATES = 'tests/integration/templates'


def run_command(runner_args, **kwargs):
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
    except subprocess.CalledProcessError as err:
        LOGGER_CLI.error('%s\n%s', error_message, err.cmd)
        return False
    except OSError as err:
        LOGGER_CLI.error('%s\n%s (%s)', error_message, err.strerror, runner_args[0])
        return False

    return True


def format_lambda_test_record(test_record):
    """Create a properly formatted Kinesis, S3, or SNS record.

    Supports a dictionary or string based data record.  Reads in
    event templates from the tests/integration/templates folder.

    Args:
        test_record: Test record metadata dict with the following structure:
            data - string or dict of the raw data
            description - a string describing the test that is being performed
            trigger - bool of if the record should produce an alert
            source - which stream/s3 bucket originated the data
            service - which aws service originated the data
            compress (optional) - if the payload needs to be gzip compressed or not

    Returns:
        dict in the format of the specific service
    """
    service = test_record['service']
    source = test_record['source']
    compress = test_record.get('compress')

    data_type = type(test_record['data'])
    if data_type == dict:
        data = json.dumps(test_record['data'])
    elif data_type in (unicode, str):
        data = test_record['data']
    else:
        LOGGER_CLI.info('Invalid data type: %s', data_type)
        return

    # Get the template file for this particular service
    template_path = os.path.join(DIR_TEMPLATES, '{}.json'.format(service))
    with open(template_path, 'r') as service_template:
        try:
            template = json.load(service_template)
        except ValueError as err:
            LOGGER_CLI.error('Error loading %s.json: %s', service, err)
            return

    if service == 's3':
        # Set the S3 object key to a random value for testing
        test_record['key'] = ('{:032X}'.format(random.randrange(16**32)))
        template['s3']['object']['key'] = test_record['key']
        template['s3']['object']['size'] = len(data)
        template['s3']['bucket']['arn'] = 'arn:aws:s3:::{}'.format(source)
        template['s3']['bucket']['name'] = source

        # Create the mocked s3 object in the designated bucket with the random key
        put_mock_s3_object(source, test_record['key'], data, 'us-east-1')

    elif service == 'kinesis':
        if compress:
            kinesis_data = base64.b64encode(zlib.compress(data))
        else:
            kinesis_data = base64.b64encode(data)

        template['kinesis']['data'] = kinesis_data
        template['eventSourceARN'] = 'arn:aws:kinesis:us-east-1:111222333:stream/{}'.format(
            source)

    elif service == 'sns':
        template['Sns']['Message'] = data
        template['EventSubscriptionArn'] = 'arn:aws:sns:us-east-1:111222333:{}'.format(
            source)
    else:
        LOGGER_CLI.info('Invalid service %s', service)

    return template


def create_lambda_function(function_name, region):
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


def encrypt_with_kms(data, region, alias):
    """Encrypt the given data with KMS."""
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


def put_mock_creds(output_name, creds, bucket, region, alias):
    """Helper function to mock encrypt creds and put on s3"""
    creds_string = json.dumps(creds)

    enc_creds = encrypt_with_kms(creds_string, region, alias)

    put_mock_s3_object(bucket, output_name, enc_creds, region)


def put_mock_s3_object(bucket, key, data, region):
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

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
from collections import namedtuple
from getpass import getpass
import json
import os
import random
import re
from StringIO import StringIO
import subprocess
import sys
import zipfile
import zlib

import boto3
from botocore.exceptions import ClientError
from moto import (
    mock_cloudwatch,
    mock_kms,
    mock_kinesis,
    mock_lambda,
    mock_s3,
    mock_dynamodb2,
)

from stream_alert_cli.logger import LOGGER_CLI
from stream_alert.rule_processor.firehose import StreamAlertFirehose

def run_command(runner_args, **kwargs):
    """Helper function to run commands with error handling.

    Args:
        runner_args (list): Commands to run via subprocess
        kwargs:
            cwd (str): A path to execute commands from
            error_message (str): Message to show if command fails
            quiet (bool): Whether to show command output or hide it

    """
    default_error_message = "An error occurred while running: {}".format(
        ' '.join(runner_args)
    )
    error_message = kwargs.get('error_message', default_error_message)
    default_cwd = 'terraform'
    cwd = kwargs.get('cwd', default_cwd)

    # Add the -force-copy flag for s3 state copying to suppress dialogs that
    # the user must type 'yes' into.
    if runner_args[0] == 'terraform':
        if runner_args[1] == 'init':
            runner_args.append('-force-copy')

    stdout_option = None
    if kwargs.get('quiet'):
        stdout_option = open(os.devnull, 'w')

    try:
        subprocess.check_call(runner_args, stdout=stdout_option, cwd=cwd)  # nosec
    except subprocess.CalledProcessError as err:
        LOGGER_CLI.error('%s\n%s', error_message, err.cmd)
        return False
    except OSError as err:
        LOGGER_CLI.error('%s\n%s (%s)', error_message, err.strerror, runner_args[0])
        return False

    return True


def continue_prompt(message=''):
    """Continue prompt to verify that a user wants to continue or not.

    This prompt's purpose is to prevent accidental changes
    that are difficult to reverse.

    Keyword Args:
        message (str): The message to display to the user

    Returns:
        bool: If the user wants to continue or not
    """
    required_responses = {'yes', 'no'}
    message = message or 'Would you like to continue?'

    response = ''
    while response not in required_responses:
        response = raw_input('\n{} (yes or no): '.format(message))

    return response == 'yes'


def tf_runner(**kwargs):
    """Terraform wrapper to build StreamAlert infrastructure.

    Steps:
        - resolve modules with `terraform get`
        - run `terraform plan` for the given targets
        - if plan is successful and user confirms prompt,
          then the infrastructure is applied

    kwargs:
        targets: a list of Terraform targets
        action: 'apply' or 'destroy'

    Returns:
        bool: True if the terraform command was successful
    """
    targets = kwargs.get('targets', [])
    action = kwargs.get('action', None)
    tf_action_index = 1  # The index to the terraform 'action'

    var_files = {'conf/lambda.json'}
    tf_opts = ['-var-file=../{}'.format(x) for x in var_files]
    tf_targets = ['-target={}'.format(x) for x in targets]
    tf_command = ['terraform', 'plan'] + tf_opts + tf_targets
    if action == 'destroy':
        tf_command.append('-destroy')

    LOGGER_CLI.debug('Resolving Terraform modules')
    if not run_command(['terraform', 'get'], quiet=True):
        return False

    LOGGER_CLI.info('Planning infrastructure')
    if not run_command(tf_command):
        return False

    if not continue_prompt():
        sys.exit(1)

    if action == 'destroy':
        LOGGER_CLI.info('Destroying infrastructure')
        tf_command[tf_action_index] = action
        tf_command.remove('-destroy')
        tf_command.append('-force')

    elif action:
        tf_command[tf_action_index] = action

    else:
        LOGGER_CLI.info('Creating infrastructure')
        tf_command[tf_action_index] = 'apply'
        tf_command.append('-refresh=false')

    if not run_command(tf_command):
        return False

    return True


def check_credentials():
    """Check for valid AWS credentials in environment variables

    Returns:
        bool: True any of the AWS env variables exist
    """
    aws_env_variables = [
        'AWS_PROFILE', 'AWS_SHARED_CREDENTIALS_FILE', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'
    ]
    env_vars_exist = any([env_var in os.environ for env_var in aws_env_variables])

    if not env_vars_exist:
        LOGGER_CLI.error('No valid AWS Credentials found in your environment!')
        LOGGER_CLI.error('Please follow the setup instructions here: '
                         'https://www.streamalert.io/account.html')
        return False

    return True


def _get_record_template(service):
    """Provides a pre-configured template that reflects incoming payload from a service

    Args:
        service (str): The service for the payload template

    Returns:
        dict: Template of the payload for the given service
    """
    if service == 's3':
        return {
            'eventVersion': '2.0',
            'eventTime': '1970-01-01T00:00:00.000Z',
            'requestParameters': {
                'sourceIPAddress': '127.0.0.1'
            },
            's3': {
                'configurationId': 'testConfigRule',
                'object': {
                    'eTag': '0123456789abcdef0123456789abcdef',
                    'sequencer': '0A1B2C3D4E5F678901',
                    'key': '<TO_BE_REPLACED>',
                    'size': '<TO_BE_REPLACED>'
                },
                'bucket': {
                    'arn': '<TO_BE_REPLACED>',
                    'name': '<TO_BE_REPLACED>',
                    'ownerIdentity': {
                        'principalId': 'EXAMPLE'
                    }
                },
                's3SchemaVersion': '1.0'
            },
            'responseElements': {
                'x-amz-id-2': 'EXAMPLE123/5678abcdefghijklambdaisawesome/mnopqrstuvwxyzABCDEFGH',
                'x-amz-request-id': 'EXAMPLE123456789'
            },
            'awsRegion': 'us-east-1',
            'eventName': 'ObjectCreated:Put',
            'userIdentity': {
                'principalId': 'EXAMPLE'
            },
            'eventSource': 'aws:s3'
        }

    elif service == 'kinesis':
        return {
            'eventID': 'shardId-000000000000:49545115243490985018280067714973144180062593244200961',
            'eventVersion': '1.0',
            'kinesis': {
                'approximateArrivalTimestamp': 1428537600,
                'partitionKey': 'partitionKey-3',
                'data': '<TO_BE_REPLACED>',
                'kinesisSchemaVersion': '1.0',
                'sequenceNumber': '49545115243490985018280067714973144582180062593244200961'
            },
            'invokeIdentityArn': 'arn:aws:iam::EXAMPLE',
            'eventName': 'aws:kinesis:record',
            'eventSourceARN': '<TO_BE_REPLACED>',
            'eventSource': 'aws:kinesis',
            'awsRegion': 'us-east-1'
        }

    elif service == 'sns':
        return {
            'EventVersion': '1.0',
            'EventSubscriptionArn': '<TO_BE_REPLACED>',
            'EventSource': 'aws:sns',
            'Sns': {
                'SignatureVersion': '1',
                'Timestamp': '1970-01-01T00:00:00.000Z',
                'Signature': 'EXAMPLE',
                'SigningCertUrl': 'EXAMPLE',
                'MessageId': '95df01b4-ee98-5cb9-9903-4c221d41eb5e',
                'Message': '<TO_BE_REPLACED>',
                'MessageAttributes': {
                    'Test': {
                        'Type': 'String',
                        'Value': 'TestString'
                    },
                    'TestBinary': {
                        'Type': 'Binary',
                        'Value': 'TestBinary'
                    }
                },
                'Type': 'Notification',
                'UnsubscribeUrl': 'EXAMPLE',
                'TopicArn': 'arn:aws:sns:EXAMPLE',
                'Subject': 'TestInvoke'
            }
        }

    elif service == 'stream_alert_app':
        return {
            'stream_alert_app': '<TO_BE_REPLACED>',
            'logs': ['<TO_BE_REPLACED>']
        }

    else:
        LOGGER_CLI.error('Unsupported service: %s', service)


def format_lambda_test_record(test_record):
    """Create a properly formatted Kinesis, S3, or SNS record.

    Supports a dictionary or string based data record.  Reads in
    event templates from the tests/integration/templates folder.

    Args:
        test_record (dict): Test record metadata dict with the following structure:
            data - string or dict of the raw data
            description - a string describing the test that is being performed
            trigger - bool of if the record should produce an alert
            source - which stream/s3 bucket originated the data
            service - which aws service originated the data
            compress (optional) - if the payload needs to be gzip compressed or not

    Returns:
        dict: in the format of the specific service
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
    record_template = _get_record_template(service)
    if not record_template:
        return

    if service == 's3':
        # Set the S3 object key to a random value for testing
        # (Bandit warns about use of insecure random generator: ignore with #nosec)
        test_record['key'] = ('{:032X}'.format(random.randrange(16**32)))  # nosec
        record_template['s3']['object']['key'] = test_record['key']
        record_template['s3']['object']['size'] = len(data)
        record_template['s3']['bucket']['arn'] = 'arn:aws:s3:::{}'.format(source)
        record_template['s3']['bucket']['name'] = source

        # Create the mocked s3 object in the designated bucket with the random key
        put_mock_s3_object(source, test_record['key'], data, 'us-east-1')

    elif service == 'kinesis':
        if compress:
            kinesis_data = base64.b64encode(zlib.compress(data))
        else:
            kinesis_data = base64.b64encode(data)

        record_template['kinesis']['data'] = kinesis_data
        record_template['eventSourceARN'] = ('arn:aws:kinesis:us-east-1:111222333:'
                                             'stream/{}'.format(source))

    elif service == 'sns':
        record_template['Sns']['Message'] = data
        record_template['EventSubscriptionArn'] = 'arn:aws:sns:us-east-1:111222333:{}'.format(
            source)

    elif service == 'stream_alert_app':
        record_template['stream_alert_app'] = source
        record_template['logs'] = [data]

    else:
        LOGGER_CLI.info('Invalid service %s', service)

    return record_template


def create_lambda_function(function_name, region):
    """Helper function to create mock lambda function"""
    if function_name.find(':') != -1:
        function_name = function_name.split(':')[0]

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


def create_delivery_stream(region, stream_name, prefix=''):
    """Create a mock AWS Kinesis Firehose stream

    Args:
        region (str): The AWS region for the boto3 client
    """
    firehose_client = boto3.client('firehose', region_name=region)

    firehose_client.create_delivery_stream(
        DeliveryStreamName=stream_name,
        S3DestinationConfiguration={
            'RoleARN': 'arn:aws:iam::123456789012:role/firehose_delivery_role',
            'BucketARN': 'arn:aws:s3:::kinesis-test',
            'Prefix': prefix,
            'BufferingHints': {
                'SizeInMBs': 123,
                'IntervalInSeconds': 124
            },
            'CompressionFormat': 'Snappy',
        }
    )


@mock_kinesis
def setup_mock_firehose_delivery_streams(config):
    """Mock Kinesis Firehose Streams for rule testing

    Args:
        config (CLIConfig): The StreamAlert config
    """
    firehose_config = config['global']['infrastructure'].get('firehose')
    if not firehose_config:
        return

    region = config['global']['account']['region']
    sa_firehose = StreamAlertFirehose(region, firehose_config, config['logs'])

    for log_type in sa_firehose.enabled_logs:
        stream_name = 'streamalert_data_{}'.format(log_type)
        prefix = '{}/'.format(log_type)
        create_delivery_stream(region, stream_name, prefix)

@mock_dynamodb2
def setup_mock_dynamodb_ioc_table(config):
    """Mock DynamoDB IOC table for rule testing

    Args:
        config (CLIConfig): The StreamAlert config
    """
    region = config['global']['account']['region']
    dynamodb_client = boto3.client('dynamodb', region_name=region)
    table_name = 'test_table_name'
    if (config['global'].get('threat_intel')
            and config['global']['threat_intel'].get('dynamodb_table')):
        table_name = config['global']['threat_intel']['dynamodb_table']

    dynamodb_client.create_table(
        AttributeDefinitions=[{
            'AttributeName': 'ioc_value',
            'AttributeType': 'S',
        }],
        KeySchema=[{
            'AttributeName': 'ioc_value',
            'KeyType': 'HASH',
        }],
        ProvisionedThroughput={
            'ReadCapacityUnits': 10,
            'WriteCapacityUnits': 10,
        },
        TableName=table_name,
    )

    dynamodb_client.put_item(
        Item={
            'ioc_value': {'S': '1.1.1.2'},
            'ioc_type': {'S': 'ip'},
            'sub_type': {'S': 'mal_ip'}
        },
        TableName=table_name
    )

    dynamodb_client.put_item(
        Item={
            'ioc_value': {'S': '0123456789abcdef0123456789abcdef'},
            'ioc_type': {'S': 'md5'},
            'sub_type': {'S': 'mal_md5'}
        },
        TableName=table_name
    )

    dynamodb_client.put_item(
        Item={
            'ioc_value': {'S': 'evil.com'},
            'ioc_type': {'S': 'domain'},
            'sub_type': {'S': 'c2_domain'}
        },
        TableName=table_name
    )

def put_mock_s3_object(bucket, key, data, region):
    """Create a mock AWS S3 object for testing

    Args:
        bucket (str): the bucket in which to place the object
        key (str): the key to use for the S3 object
        data (str): the actual value to use for the object
        region (str): the aws region to use for this boto3 client
    """
    s3_client = boto3.client('s3', region_name=region)
    try:
        # Check if the bucket exists before creating it
        s3_client.head_bucket(Bucket=bucket)
    except ClientError:
        s3_client.create_bucket(Bucket=bucket)

    s3_client.put_object(
        Body=data,
        Bucket=bucket,
        Key=key,
        ServerSideEncryption='AES256'
    )


def mock_me(context):
    """Decorator function for wrapping framework in mock calls
    for running local tests, and omitting mocks if testing live

    Args:
        context (namedtuple): A constructed aws context object
    """
    def wrap(func):
        """Wrap the returned function with or without mocks"""
        if context.mocked:
            @mock_cloudwatch
            @mock_lambda
            @mock_s3
            @mock_kms
            @mock_kinesis
            def mocked(options, context):
                """This function is now mocked using moto mock decorators to
                override any boto3 calls. Wrapping this function here allows
                us to mock out all calls that happen below this scope."""
                return func(options, context)
            return mocked

        def unmocked(options, context):
            """This function will remain unmocked and operate normally"""
            return func(options, context)
        return unmocked

    return wrap


def get_context_from_config(cluster, config):
    """Return a constructed context to be used for testing

    Args:
        cluster (str): Name of the cluster to be used for live testing
        config (CLIConfig): Configuration for this StreamAlert setup that
            includes cluster info, etc that can be used for constructing
            an aws context object
    """
    context = namedtuple('aws_context', ['invoked_function_arn',
                                         'function_name'
                                         'mocked'])

    # Return a mocked context if the cluster is not provided
    # Otherwise construct the context from the config using the cluster
    if not cluster:
        region = config['global']['account']['region']
        context.invoked_function_arn = (
            'arn:aws:lambda:{}:123456789012:'
            'function:test_streamalert_processor:development').format(region)
        context.function_name = 'test_streamalert_alert_processor'
        context.mocked = True
    else:
        prefix = config['global']['account']['prefix']
        account = config['global']['account']['aws_account_id']
        region = config['global']['account']['region']
        function_name = '{}_{}_streamalert_alert_processor'.format(prefix, cluster)
        arn = 'arn:aws:lambda:{}:{}:function:{}:testing'.format(
            region, account, function_name)

        context.invoked_function_arn = arn
        context.function_name = function_name
        context.mocked = False

    return context

def user_input(requested_info, mask, input_restrictions):
    """Prompt user for requested information

    Args:
        requested_info (str): Description of the information needed
        mask (bool): Decides whether to mask input or not

    Returns:
        str: response provided by the user
    """
    # pylint: disable=protected-access
    response = ''
    prompt = '\nPlease supply {}: '.format(requested_info)

    if not mask:
        while not response:
            response = raw_input(prompt)

        # Restrict having spaces or colons in items (applies to things like
        # descriptors, etc)
        valid_response = False
        if isinstance(input_restrictions, re._pattern_type):
            valid_response = input_restrictions.match(response)
            if not valid_response:
                LOGGER_CLI.error('The supplied input should match the following '
                                 'regular expression: %s', input_restrictions.pattern)
        elif callable(input_restrictions):
            # Functions can be passed here to perform complex validation of input
            # Transform the response with the validating function
            response = input_restrictions(response)
            valid_response = response is not None and response is not False
            if not valid_response:
                LOGGER_CLI.error('The supplied input failed to pass the validation '
                                 'function: %s', input_restrictions.__doc__)
        else:
            valid_response = not any(x in input_restrictions for x in response)
            if not valid_response:
                restrictions = ', '.join('\'{}\''.format(restriction)
                                         for restriction in input_restrictions)
                LOGGER_CLI.error('The supplied input should not contain any of the following: %s',
                                 restrictions)

        if not valid_response:
            return user_input(requested_info, mask, input_restrictions)
    else:
        while not response:
            response = getpass(prompt=prompt)

    return response


def load_test_file(path):
    """Helper to json load the contents of a file with some error handling

    Args:
        path (str): Relative path to file on disk

    Returns:
        dict: Loaded JSON from test event file
    """
    message_template = 'Improperly formatted file ({}): {}'
    with open(path, 'r') as test_event_file:
        try:
            contents = json.load(test_event_file)
        except (ValueError, TypeError) as err:
            message = message_template.format(path, err.message)
            return False, message

        # Make sure the test event file is formatted in the way we expect
        if not (isinstance(contents, dict) and 'records' in contents):
            message = message_template.format(path, 'File must be a dict (JSON '
                                              'object) with top level key \'records\'')

            return False, message

        return contents, None


def get_rules_from_test_events(test_files_dir):
    """Helper to return all of the rules being tested with test events

    Args:
        test_files_dir (str): Path indicating where test files reside

    Returns:
        set: A collection of all of the rules being tested
    """
    test_file_info = get_rule_test_files(test_files_dir)
    all_rules = set()
    for path in test_file_info.values():
        events, _ = load_test_file(path)
        if not events:
            continue

        for test_event in events['records']:
            if 'trigger_rules' not in test_event:
                continue

            all_rules.update(test_event['trigger_rules'])

    return all_rules


def get_rule_test_files(test_files_dir):
    """Helper to get rule files to be tested

    Args:
        test_files_dir (str): Path indicating where test files reside

    Returns:
        dict:  Information about test files on disk, where the key is the
            base name of the file and the value is the relative path to the file
    """
    return {os.path.splitext(event_file)[0]: os.path.join(root, event_file)
            for root, _, test_event_files in os.walk(test_files_dir)
            for event_file in test_event_files}

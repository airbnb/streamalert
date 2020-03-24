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
from datetime import datetime
import uuid
from io import BytesIO
import zipfile

import boto3
from botocore.exceptions import ClientError

from streamalert.shared.helpers.aws_api_client import AwsS3


class MockLambdaClient:
    """http://boto3.readthedocs.io/en/latest/reference/services/lambda.html"""

    def __init__(self, name, **kwargs):
        self.region = kwargs.get('region')
        self.throw_exception = kwargs.get('throw_exception')
        self.current_version = 10
        self.name = name

    def publish_version(self, **kwargs):
        """Publish a new version of the mock Lambda function."""
        # Test error handling
        if self.throw_exception:
            raise ClientError({'Error': {}}, 'test')

        function_name = kwargs.get('FunctionName')
        code_sha_256 = kwargs.get('CodeSha256')
        description = kwargs.get('Description')

        return {
            'FunctionName': function_name,
            'FunctionArn': 'arn:aws:lambda:region:account-id:function:{}'.format(function_name),
            'Runtime': 'python3.7',
            'Role': 'string',
            'Handler': 'main.handler',
            'CodeSize': 128,
            'Description': description,
            'Timeout': 60,
            'MemorySize': 128,
            'LastModified': 'string',
            'CodeSha256': code_sha_256,
            'Version': self.current_version + 1
        }


class MockAthenaClient:
    """http://boto3.readthedocs.io/en/latest/reference/services/athena.html"""

    class MockAthenaPaginator:
        """Mock class for paginating athena results"""
        def __init__(self, func, pages):
            self._func = func
            self._pages = pages

        def paginate(self, **kwargs):
            """Yield the number of pages requested"""
            for _ in range(self._pages):
                yield self._func(**kwargs)

    def __init__(self, **kwargs):
        self.query_executions = {}
        self.results = kwargs.get('results', [{'test': 'test'}])
        self.result_state = kwargs.get('result_state', 'SUCCEEDED')
        self.raise_exception = False

    @staticmethod
    def get_start_query_execution(**kwargs):
        """Get query start parameters."""
        return {
            'QueryExecution': {
                'QueryExecutionId': str(uuid.uuid4()),
                'Query': kwargs.get('QueryString'),
                'ResultConfiguration': {
                    'OutputLocation': kwargs.get('OutputLocation', ''),
                    'EncryptionConfiguration': kwargs.get('EncryptionConfiguration', {})
                },
                'QueryExecutionContext': kwargs.get('QueryExecutionContext', {}),
                'Status': {
                    'State': 'QUEUED',
                    'StateChangeReason': 'string',
                    'SubmissionDateTime': datetime(2017, 1, 1),
                    'CompletionDateTime': datetime(2017, 1, 1)
                },
                'Statistics': {
                    'EngineExecutionTimeInMillis': 123,
                    'DataScannedInBytes': 123
                }
            }
        }

    def start_query_execution(self, **kwargs):
        """Start an Athena Query Execution."""
        if self.raise_exception:
            raise ClientError({'Error': {'Code': 10}}, 'InvalidRequestException')
        new_query_execution = self.get_start_query_execution(**kwargs)
        new_query_id = new_query_execution['QueryExecution']['QueryExecutionId']
        self.query_executions[new_query_id] = new_query_execution

        return {
            'QueryExecutionId': new_query_id
        }

    def get_query_execution(self, **kwargs):
        """Get the status of an Athena Query Execution."""
        query_execution = self.query_executions.get(kwargs['QueryExecutionId'])
        query_execution['QueryExecution']['Status']['State'] = self.result_state

        return query_execution

    def get_query_results(self, **kwargs):  # pylint: disable=unused-argument
        """Get the results of a executed query"""
        return {'ResultSet': {'Rows': self.results if self.results else []}}

    def get_paginator(self, func_name):
        """Return a MockAthenaPaginator to yield results"""
        attr = getattr(self, func_name)
        return MockAthenaClient.MockAthenaPaginator(attr, 4)


def _make_lambda_package():
    """Helper function to create mock lambda package"""
    mock_lambda_function = """
def handler(event, context):
    return event
"""
    package_output = BytesIO()
    package = zipfile.ZipFile(package_output, 'w', zipfile.ZIP_DEFLATED)
    package.writestr('function.zip', mock_lambda_function)
    package.close()
    package_output.seek(0)

    return package_output.read()


def create_lambda_function(function_name, region):
    """Helper function to create mock lambda function"""
    if function_name.find(':') != -1:
        function_name = function_name.split(':')[0]

    boto3.client('lambda', region_name=region).create_function(
        FunctionName=function_name,
        Runtime='python3.7',
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


def setup_mock_alerts_table(table_name):
    """Create a mock DynamoDB alerts table used by rules engine, alert processor, alert merger"""
    put_mock_dynamod_data(
        table_name,
        {
            'AttributeDefinitions': [
                {
                    'AttributeName': 'RuleName',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'AlertID',
                    'AttributeType': 'S'
                }
            ],
            'KeySchema': [
                {
                    'AttributeName': 'RuleName',
                    'KeyType': 'HASH'
                },
                {
                    'AttributeName': 'AlertID',
                    'KeyType': 'RANGE'
                }
            ],
        },
        []
    )


def setup_mock_rules_table(table_name):
    """Create a mock DynamoDB rules table used by the CLI, rules engine, and rule promoter"""
    put_mock_dynamod_data(
        table_name,
        {
            'AttributeDefinitions': [
                {
                    'AttributeName': 'RuleName',
                    'AttributeType': 'S'
                }
            ],
            'KeySchema': [
                {
                    'AttributeName': 'RuleName',
                    'KeyType': 'HASH'
                }
            ]
        },
        []
    )


def put_mock_dynamod_data(table_name, schema, data):
    """
    Params:
        table_name (str)
        schema (dict)
            A dynamodb schema. You will need the following keys:
                * AttributeDefinitions
                    List of attribute definition. Each attribute definition has 2 fields:
                        * AttributeName
                        * AttributeType
                * KeySchema
                    List of key definitions. Each key definition has 2 fields:
                        * AttributeName
                        * KeyType
        data (list[dict])
            A list of individual dict elements, mapping columns to values.
    """

    schema['TableName'] = table_name
    schema['ProvisionedThroughput'] = {
        'ReadCapacityUnits': 5,
        'WriteCapacityUnits': 5
    }

    boto3.client('dynamodb', region_name='us-east-1').create_table(**schema)

    table = boto3.resource('dynamodb', region_name='us-east-1').Table(table_name)
    with table.batch_writer() as batch:
        for datum in data:
            batch.put_item(Item=datum)


def put_mock_s3_object(bucket, key, data, region='us-east-1'):
    """Create a mock AWS S3 object for testing

    Args:
        bucket (str): the bucket in which to place the object
        key (str): the key to use for the S3 object
        data (str): the actual value to use for the object
        region (str): the aws region to use for this boto3 client
    """
    try:
        AwsS3.head_bucket(bucket, region=region)
    except ClientError:
        AwsS3.create_bucket(bucket, region=region)

    AwsS3.put_object(data, bucket=bucket, key=key, region=region)

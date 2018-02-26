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
from datetime import datetime
import uuid

from botocore.exceptions import ClientError


class MockLambdaClient(object):
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
            'Runtime': 'python2.7',
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


class MockAthenaClient(object):
    """http://boto3.readthedocs.io/en/latest/reference/services/athena.html"""

    def __init__(self, **kwargs):
        self.query_executions = {}
        self.results = kwargs.get('results', [{'test': 'test'}])
        self.result_state = kwargs.get('result_state', 'SUCCEEDED')

    def get_start_query_execution(self, **kwargs):  # pylint: disable=no-self-use
        """Get query start parameters."""
        return {
            'QueryExecution': {
                'QueryExecutionId': uuid.uuid4(),
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
        """Start an Athena Query Exectuion."""
        new_query_execution = self.get_start_query_execution(**kwargs)
        new_query_id = new_query_execution['QueryExecution']['QueryExecutionId']
        self.query_executions[new_query_id] = new_query_execution

        return {
            'QueryExecutionId': new_query_id
        }

    def get_query_execution(self, **kwargs):
        """Get the status of an Athena Query Exectuion."""
        query_execution = self.query_executions.get(kwargs['QueryExecutionId'])
        query_execution['QueryExecution']['Status']['State'] = self.result_state

        return query_execution

    def get_query_results(self, **kwargs):  # pylint: disable=unused-argument
        """Get the results of a executed query"""
        return {'ResultSet': {'Rows': [{'Data': self.results}] if self.results else []}}


class MockSqsClient(object):
    """Mock SQS client"""

    def __init__(self, **kwargs):
        self.region = kwargs.get('region')
        self.failed = kwargs.get('failed')

    def delete_message_batch(self, **kwargs): # pylint: disable=unused-argument
        """Mock error handling in SQS delete_message_batch method"""
        if self.failed:
            return {'Failed': [{'Id': '1'}]}

        return {'Successful': [{'foo': 'bar'}]}

    def list_queues(self, **kwargs): # pylint: disable=unused-argument,no-self-use
        """Mock list_queues method"""
        return {'QueueUrls': ['url_foo', 'url_bar']}

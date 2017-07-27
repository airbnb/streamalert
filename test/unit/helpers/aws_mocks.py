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
from datetime import datetime

import uuid


def get_start_query_execution(**kwargs):
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


class MockAthenaClient(object):
    """http://boto3.readthedocs.io/en/latest/reference/services/athena.html#client"""

    def __init__(self, **kwargs):
        self.query_executions = {}
        self.results = kwargs.get('results', [{'test': 'test'}])
        self.result_state = kwargs.get('result_state', 'SUCCEEDED')

    def start_query_execution(self, **kwargs):
        """Start an Athena Query Exectuion."""
        new_query_execution = get_start_query_execution(**kwargs)
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

    def get_query_results(self, **kwargs):
        """Get the results of a executed query"""
        if self.results:
            return {'ResultSet': {'Rows': [{'Data': self.results}]}}
        else:
            return {'ResultSet': {'Rows': []}}

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
from botocore.exceptions import ClientError, ParamValidationError
from mock import Mock

from tests.unit.threat_intel_downloader import FUNCTION_NAME, REGION


class MockSSMClient(object):
    """Helper mock class to act as the ssm boto3 client"""

    def __init__(self, valid_creds=0):
        self._parameters = {'api_user': 'test_api_user', 'api_key': 'test_api_key'}
        self.raise_exception = False
        self.valid_creds = valid_creds

    def get_parameters(self, **kwargs): # pylint: disable=unused-argument
        """Mocked get_parameters function that returns a list of values for the keys from a dict

        Keyword Arguments:
            Name (list[str]): The names of the parameters to retrieve

        Returns:
            dict: Parameter dictionary containing the value for these parameter names
        """
        if self.raise_exception:
            err = {'Error': {'Code': 403, 'Message': 'error getting parameters'}}
            raise ClientError(err, 'get_parameters')

        return mock_ssm_response(valid_creds=self.valid_creds)


class MockLambdaClient(object):
    """Helper mock class to act as the ssm boto3 client"""
    _raise_exception = False

    @classmethod
    def invoke(cls, **kwargs):
        """Mocked invoke function that returns a reponse mimicking boto3's reponse

        Keyword Arguments:
            FuncitonName (str): The AWS Lambda function name being invoked
            InvocationType (str): Type of invocation (typically 'Event')
            Payload (str): Payload in string or file format to send to lambda
            Qualifier (str): Alias for fully qualified AWS ARN

        Returns:
            dict: Response dictionary containing a fake RequestId
        """
        if cls._raise_exception:
            # Turn of the raise exception boolean so we don't do this next time
            cls._raise_exception = not cls._raise_exception
            err = {'Error': {'Code': 400, 'Message': 'raising test exception'}}
            raise ClientError(err, 'invoke')

        req_keywords = {'FunctionName', 'InvocationType', 'Payload'}
        key_diff = req_keywords.difference(set(kwargs))
        if key_diff:
            message = 'required keyword missing: {}'.format(', '.join(key_diff))
            err = {'Error': {'Code': 400, 'Message': message}}
            raise ClientError(err, 'invoke')

        if not isinstance(kwargs['Payload'], (str, bytearray)):
            if not hasattr(kwargs['Payload'], 'read'):
                err = ('Invalid type for parameter Payload, value: {}, type: {}, '
                       'valid types: <type \'str\'>, <type \'bytearray\'>, '
                       'file-like object').format(kwargs['Payload'], type(kwargs['Payload']))
                raise ParamValidationError(response=err)

        return {'ResponseMetadata': {'RequestId': '9af88643-7b3c-43cd-baae-addb73bb4d27'}}


def get_mock_context():
    """Helper function to create a fake context object using Mock"""
    arn = 'arn:aws:lambda:{}:123456789012:function:{}:development'
    context = Mock(invoked_function_arn=(arn.format(REGION, FUNCTION_NAME)),
                   function_name=FUNCTION_NAME,
                   get_remaining_time_in_millis=Mock(return_value=100))

    return context

class MockRequestsResponse(object): # pylint: disable=too-few-public-methods
    """Mocking class to mock requests.get() call"""
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        """Return data in json format"""
        return self.json_data

def mock_requests_get(*args, **kwargs): # pylint: disable=unused-argument
    """Method to mock requests.get() call"""
    return MockRequestsResponse({
        "key1": "value1",
        "objects": [
            {
                'value': 'malicious_domain.com',
                'itype': 'c2_domain',
                'source': 'ioc_source',
                'type': 'domain',
                'expiration_ts': '2017-12-31T00:01:02.123Z',
                'key1': 'value1',
                'key2': 'value2'
            },
            {
                'value': 'malicious_domain2.com',
                'itype': 'c2_domain',
                'source': 'test_source',
                'type': 'domain',
                'expiration_ts': '2017-11-30T00:01:02.123Z',
                'key1': 'value1',
                'key2': 'value2'
            }
        ],
        "meta": {
            "next": None,
            "offset": 100
            }
        }, 200)

def mock_ssm_response(valid_creds=0):
    """Mock SSM get_parameters response

    Args:
        valid_creds (integer): 2, 1 or 0

    response case 1: both api_user and api_key are returned
        return
            {
                'Parameters': [
                    {
                        'Name': 'threat_intel_downloader_api_creds',
                        'Value': '{"api_user": "test_user", "api_key": "test_key"}',
                    },
                    {
                        'Name': 'ti_test_state',
                        'Value': '{"next_url": "test_next_url", "continue_invoke": "False"}',
                    },
                ],
                'InvalidParameters': [
                    'invalid_foo',
                ]
            }
    response case 2: only one cred (either api_user or api_key) is returned
        return
            {
                'Parameters': [
                    {
                        'Name': 'threat_intel_downloader_api_creds',
                        'Value': '{"api_user": "test_user", "api_key": "test_key"}',
                    }
                ],
                'InvalidParameters': [
                    'invalid_foo',
                ]
            }
    response case 3: no valid cred is returned
        return
            {
                'Parameters': [{}],
                'InvalidParameters': [
                    'invalid_foo',
                ]
            }
    """
    valid_creds = valid_creds % 3
    params = {
        'threat_intel_downloader_api_creds': '{"api_user": "test_user", "api_key": "test_key"}',
        'ti_test_state': '{"next_url": "test_next_url", "continue_invoke": "False"}'
    }
    response = [{'Name': pair[0], 'Value': pair[1]} for pair in params.items()[:valid_creds]]

    return {
        'Parameters': response,
        'InvalidParameters': [
            'invalid_foo',
        ]
    }

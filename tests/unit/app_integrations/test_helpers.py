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

from botocore.exceptions import ClientError, ParamValidationError
from mock import Mock

from tests.unit.app_integrations import FUNCTION_NAME, REGION


class MockSSMClient(object):
    """Helper mock class to act as the ssm boto3 client"""
    _PARAMETERS = dict()

    @classmethod
    def put_parameter(cls, **kwargs):
        """Mocked put_parameter function that adds key/value pairs to a dict"""
        if kwargs.get('Name') in cls._PARAMETERS and not kwargs.get('Overwrite'):
            return

        cls._PARAMETERS[kwargs.get('Name')] = kwargs.get('Value')

    @classmethod
    def get_parameter(cls, **kwargs):
        """Mocked get_parameter function that returns a value for the key from a dict

        Keyword Arguments:
            Name (str): The name of the parameter to retrieve

        Returns:
            dict: Parameter dictionary containing this parameter's value
        """
        # Raise a botocore ClientError if the param doesn't exist
        if kwargs.get('Name') not in cls._PARAMETERS:
            err = {'Error': {'Code': 403, 'Message': 'parameter does not exist'}}
            raise ClientError(err, 'get_parameter')

        return {'Parameter': {'Value': cls._PARAMETERS.get(kwargs.get('Name'))}}

    @classmethod
    def get_parameters(cls, **kwargs):
        """Mocked get_parameters function that returns a list of values for the keys from a dict

        Keyword Arguments:
            Name (list[str]): The names of the parameters to retrieve

        Returns:
            dict: Parameter dictionary containing the value for these parameter names
        """
        return {'Parameters': [{'Name': name, 'Value': cls._PARAMETERS[name]}
                               for name in kwargs.get('Names') if name in cls._PARAMETERS],
                'InvalidParameters': [name for name in kwargs.get('Names')
                                      if name not in cls._PARAMETERS]}


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


def put_mock_params():
    """Helper function to put mock parameters in parameter store for an app integration"""
    config = {'cluster': 'unit_test_cluster',
              'app_name': 'unit_app',
              'prefix': 'unit_test_prefix',
              'type': 'duo_auth',
              'interval': 'rate(1 hour)'}
    MockSSMClient.put_parameter(Name='{}_config'.format(FUNCTION_NAME),
                                Value=json.dumps(config),
                                Overwrite=True)

    auth = {'api_hostname': 'api-abcdef12.duosecurity.com',
            'integration_key': 'DI1234567890ABCDEF12',
            'secret_key': 'unit_secret_key'}
    MockSSMClient.put_parameter(Name='{}_auth'.format(FUNCTION_NAME),
                                Value=json.dumps(auth),
                                Overwrite=True)

    state = {'last_timestamp': '1505591798',
             'current_state': 'running'}
    MockSSMClient.put_parameter(Name='{}_state'.format(FUNCTION_NAME),
                                Value=json.dumps(state),
                                Overwrite=True)

def get_valid_config_dict():
    """Helper function to get a dict that is reflective of a valid AppConfig"""
    return {
        'type': 'duo_auth',
        'cluster': 'unit_test_cluster',
        'prefix': 'unit_test_prefix',
        'app_name': 'unit_app',
        'interval': 'rate(1 hour)',
        'region': 'us-east-1',
        'account_id': '123456789012',
        'function_name': FUNCTION_NAME,
        'qualifier': 'production',
        'last_timestamp': 1505316432,
        'current_state': 'succeeded',
        'auth': {
            'api_hostname': 'api-abcdef12.duosecurity.com',
            'integration_key': 'DIABCDEFGHIJKLMN1234',
            'secret_key': 'abcdefghijklmnopqrstuvwxyz1234567890ABCD'

        }
    }



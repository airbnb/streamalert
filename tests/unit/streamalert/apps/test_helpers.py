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
from botocore.exceptions import ClientError, ParamValidationError


def put_mock_params(app_type):
    """Helper function to put mock parameters in parameter store for an app integration"""
    params = {
        f'{app_type}_state': {
            'last_timestamp': _get_formatted_timestamp(app_type),
            'current_state': 'succeeded'},
        f'{app_type}_auth': _get_auth_info(app_type)}

    ssm_client = boto3.client('ssm')
    for key, value in params.items():
        ssm_client.put_parameter(
            Name=key,
            Value=json.dumps(value),
            Type='SecureString',
            Overwrite=True
        )


def _get_auth_info(app_type):
    """Helper to return valid auth info for a given app type"""
    if app_type.startswith('duo'):
        return {
            'api_hostname': 'api-abcdef12.duosecurity.com',
            'integration_key': 'DI1234567890ABCDEF12',
            'secret_key': 'abcdefghijklmnopqrstuvwxyz1234567890ABCD'
        }
    if app_type.startswith('onelogin'):
        return {
            'region': 'us',
            'client_secret': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'client_id': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        }
    if app_type.startswith('gsuite'):
        return {
            'delegation_email': 'test@email.com',
            'keyfile': {
                'type': 'service_account',
                'project_id': 'myapp-123456',
                'private_key_id': 'a5427e441234a5f416ab0a2e5d759752ef69fbf1',
                'private_key': ('-----BEGIN PRIVATE KEY-----\nVGhpcyBpcyBub3QgcmVhbA==\n'
                                '-----END PRIVATE KEY-----\n'),
                'client_email': 'a-test-200%40myapp-123456.iam.gserviceaccount.com',
                'client_id': '316364948779587921167',
                'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
                'token_uri': 'https://accounts.google.com/o/oauth2/token',
                'auth_provider_x509_cert_url': 'https://www.googleapis.com/oauth2/v1/certs',
                'client_x509_cert_url': ('https://www.googleapis.com/robot/v1/metadata/x509/'
                                         'a-test-200%40myapp-123456.iam.gserviceaccount.com')
            }
        }
    if app_type.startswith('box'):
        return {
            'keyfile': {
                'boxAppSettings': {
                    'clientID': 'sc0ikmesi43elk4rxus11sbee1najitr',
                    'clientSecret': '9ccOBWPh8ab5wHN2uGy0nFOrUtY82xcZ',
                    'appAuth': {
                        'publicKeyID': 'zqxhbd44',
                        'privateKey': ('-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
                                       'VGhpcyBpcyBub3QgcmVhbA==\n-----END ENCRYPTED '
                                       'PRIVATE KEY-----\n'),
                        'passphrase': 'e8a88b08eff2797234d6313686f7bad7'
                    }
                },
                'enterpriseID': '12345678'
            }
        }
    if app_type == 'aliyun':
        return {
            'access_key_id': 'ACCESS_KEY_ID',
            'access_key_secret': 'ACCESS_KEY_SECRET',
            'region_id': 'REGION_ID'
        }
    if app_type == 'salesforce':
        return {
            'client_id': 'CLIENT_ID',
            'client_secret': 'CLIENT_SECRET',
            'username': 'USERNAME',
            'password': 'PASSWORD',
            'security_token': 'SECURITY_TOKEN'
        }
    if app_type == 'slack':
        return {
            'auth_token': 'xoxp-aaaaaaa-111111111-eeeeeeeeee-fffffff'
        }

    # Fill this out with future supported apps/services

    # Return basic test info
    return {
        'host': 'foobar',
        'secret': 'barfoo'
    }


class MockLambdaClient:
    """Helper mock class to act as the ssm boto3 client"""
    _raise_exception = False

    @classmethod
    def invoke(cls, **kwargs):
        """Mocked invoke function that returns a reponse mimicking boto3's reponse

        Keyword Args:
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
        if key_diff := req_keywords.difference(set(kwargs)):
            message = f"required keyword missing: {', '.join(key_diff)}"
            err = {'Error': {'Code': 400, 'Message': message}}
            raise ClientError(err, 'invoke')

        if not isinstance(
                kwargs['Payload'], (str, bytearray)) and not hasattr(
                kwargs['Payload'], 'read'):
            err = f"Invalid type for parameter Payload, value: {kwargs['Payload']}, type: {type(kwargs['Payload'])}, valid types: <type \'str\'>, <type \'bytearray\'>, file-like object"

            raise ParamValidationError(response=err)

        return {'ResponseMetadata': {'RequestId': '9af88643-7b3c-43cd-baae-addb73bb4d27'}}


def _get_formatted_timestamp(app_type):
    """Different services required different date formats - return the proper format here"""
    if app_type.startswith('duo'):
        return 1505316432
    if app_type.startswith('onelogin'):
        return '2017-10-10T22:03:57Z'
    if app_type.startswith('gsuite') or app_type == 'salesforce':
        return '2017-06-17T15:39:18.460Z'
    if app_type.startswith('box'):
        return '2017-10-27T12:31:22-07:00'
    if app_type == 'slack':
        return 1422922593
    return '2018-07-23T15:42:11Z' if app_type == 'aliyun' else 1234567890


def get_event(app_type):
    """Helper function to get a dict that is reflective of a valid input event for an App"""
    return {
        'app_type': app_type,
        'schedule_expression': 'rate(10 minutes)',
        'destination_function_name':
            'unit_test_prefix_unit_test_cluster_streamalert_classifier'
    }


def list_salesforce_api_versions():
    """Helper function to return a list of supported API versions"""
    return [
        {
            "version": "20.0",
            "label": "Winter '11",
            "url": "/services/data/v20.0"
        },
        {
            "version": "21.0",
            "label": "Spring '11",
            "url": "/services/data/v21.0"
        },
        {
            "version": "26.0",
            "label": "Winter '13",
            "url": "/services/data/v26.0"
        }
    ]


def get_salesforce_log_files():
    """Helper function to get a list available log files"""
    return {
        "totalSize": 2,
        "done": True,
        "records": [
            {
                "attributes": {
                    "type": "EventLogFile",
                    "url": "/services/data/v32.0/sobjects/EventLogFile/0ATD00001bROAQ"
                },
                "Id": "0ATD000000001bROAQ",
                "EventType": "API",
                "LogFile": "/services/data/v32.0/sobjects/EventLogFile/0ATD00001bROAQ/LogFile",
                "LogDate": "2014-03-14T00:00:00.000+0000",
                "LogFileLength": 2692.0
            },
            {
                "attributes": {
                    "type": "EventLogFile",
                    "url": "/services/data/v32.0/sobjects/EventLogFile/0ATD000000001SdOAI"
                },
                "Id": "0ATD000000001SdOAI",
                "EventType": "API",
                "LogFile": "/services/data/v32.0/sobjects/EventLogFile/0ATD00001SdOAI/LogFile",
                "LogDate": "2014-03-13T00:00:00.000+0000",
                "LogFileLength": 1345.0
            }
        ]
    }

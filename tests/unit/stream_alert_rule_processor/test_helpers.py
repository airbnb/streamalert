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

from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError, ParamValidationError

from mock import Mock

from stream_alert.rule_processor.classifier import StreamClassifier
from stream_alert.rule_processor.payload import load_stream_payload
from tests.unit.stream_alert_rule_processor import FUNCTION_NAME, REGION


def get_mock_context():
    """Create a fake context object using Mock"""
    arn = 'arn:aws:lambda:{}:123456789012:function:{}:development'
    context = Mock(invoked_function_arn=(arn.format(REGION, FUNCTION_NAME)),
                   function_name=FUNCTION_NAME)

    return context


def get_valid_config():
    """Helper function to return a valid config for the rule processor. This
    simulates what stream_alert.rule_processor.load_config will return in a
    very simplified format.

    Returns:
        dict: contents of a valid config file
    """
    return {
        'logs': {
            'json_log': {
                'schema': {
                    'name': 'string'
                },
                'parser': 'json'
            },
            'csv_log': {
                'schema': {
                    'data': 'string',
                    'uid': 'integer'
                },
                'parser': 'csv'
            }
        },
        'sources': {
            'kinesis': {
                'stream_1': {
                    'logs': [
                        'json_log',
                        'csv_log'
                    ]
                }
            }
        },
        'types': {
            'log_type1': {
                'command': ['cmdline', 'commandline']
            }
        },
        'global': {
            'account': {
                'aws_account_id': '123456123456'
            },
            'infrastructure': {
                'monitoring': {
                    'create_sns_topic': True
                }
            }
        }
    }

def convert_events_to_kinesis(raw_records):
    """Given a list of pre-defined raw records, make a valid kinesis test event"""
    return {'Records': [make_kinesis_raw_record('unit_test_default_stream',
                                                json.dumps(record))
                        for record
                        in raw_records]}


def get_valid_event(count=1, **kwargs):
    """Return a valid event with the given number of records."""
    default_record = {
        'unit_key_01': '100',
        'unit_key_02': 'another bogus value'
    }
    record_data = kwargs.get('record', default_record)

    data_json = json.dumps(record_data)
    raw_record = make_kinesis_raw_record('unit_test_default_stream', data_json)

    return {'Records': [raw_record for _ in range(count)]}


def load_and_classify_payload(config, service, entity, raw_record):
    """Return a loaded and classified payload."""
    # prepare the payloads
    payload = load_stream_payload(service, entity, raw_record)

    payload = list(payload.pre_parse())[0]
    classifier = StreamClassifier(config=config)
    classifier.load_sources(service, entity)
    classifier.classify_record(payload)

    return payload


def make_kinesis_raw_record(kinesis_stream, kinesis_data):
    """Helper for creating the kinesis raw record"""
    raw_record = {
        'eventID': 'unit test event id',
        'eventSource': 'aws:kinesis',
        'eventSourceARN': 'arn:aws:kinesis:us-east-1:123456789012:stream/{}'.format(kinesis_stream),
        'kinesis': {
            'data': base64.b64encode(kinesis_data)}}
    return raw_record


def make_sns_raw_record(topic_name, sns_data):
    """Helper for creating the sns raw record"""
    raw_record = {
        'EventSource': 'aws:kinesis',
        'EventSubscriptionArn': 'arn:aws:sns:us-east-1:123456789012:{}'.format(topic_name),
        'Sns': {
            'MessageId': 'unit test message id',
            'Message': sns_data}}
    return raw_record


def make_s3_raw_record(bucket, key):
    """Helper for creating the s3 raw record"""
    # size = len(s3_data)
    raw_record = {
        's3': {
            'configurationId': 'testConfigRule',
            'object': {
                'eTag': '0123456789abcdef0123456789abcdef',
                'sequencer': '0A1B2C3D4E5F678901',
                'key': key,
                'size': 100
            },
            'bucket': {
                'arn': 'arn:aws:s3:::mybucket',
                'name': bucket,
                'ownerIdentity': {
                    'principalId': 'EXAMPLE'
                }
            }
        },
        'awsRegion': 'us-east-1'
    }
    return raw_record

def mock_normalized_records(default_data=None):
    """Morck records which have been normalized"""
    if not default_data:
        default_data = [
            {
                'account': 12345,
                'region': '123456123456',
                'detail': {
                    'eventName': 'ConsoleLogin',
                    'userIdentity': {
                        'userName': 'alice',
                        'accountId': '12345'
                    },
                    'sourceIPAddress': '1.1.1.2',
                    'recipientAccountId': '12345'
                },
                'source': '1.1.1.2',
                'streamalert:normalization': {
                    'sourceAddress': [['detail', 'sourceIPAddress'], ['source']],
                    'usernNme': [['detail', 'userIdentity', 'userName']]
                }
            },
            {
                'domain': 'evil.com',
                'pc_name': 'test-pc',
                'date': 'Dec 1st, 2016',
                'data': 'ABCDEF',
                'streamalert:normalization': {
                    'destinationDomain': [['domain']]
                }
            },
            {
                'domain': 'evil2.com',
                'pc_name': 'test-pc',
                'date': 'Dec 1st, 2016',
                'data': 'ABCDEF',
                'streamalert:normalization': {
                    'destinationDomain': [['domain']]
                }
            },
            {
                'process_md5': 'abcdef0123456789',
                'server': 'test-server',
                'date': 'Dec 2nd, 2016',
                'data': 'Foo',
                'streamalert:normalization': {
                    'fileHash': [['process_md5']]
                }
            }
        ]

    kinesis_payload = []
    for record in default_data:
        entity = 'unit_test_entity'
        raw_record = make_kinesis_raw_record(entity, 'None')
        payload = load_stream_payload('kinesis', entity, raw_record)
        payload = payload.pre_parse().next()
        payload.pre_parsed_record = record
        kinesis_payload.append(payload)

    return kinesis_payload

class MockDynamoDBClient(object):
    """Helper mock class to act as dynamodb client"""
    def __init__(self, **kwargs):
        self.exception = kwargs.get('exception', False)
        self.has_unprocessed_keys = kwargs.get('unprocesed_keys', False)

    def batch_get_item(self, **kwargs):
        """Mock batch_get_item method and return mimicking dynamodb response
        Keyword Argments:
            exception (bool): True raise exception.

        Returns:
            (dict): Response dictionary containing fake results.
        """
        if self.exception:
            err = {'Error': {'Code': 400, 'Message': 'raising test exception'}}
            raise ClientError(err, 'batch_get_item')

        if not kwargs.get('RequestItems'):
            err = {
                'Error': {
                    'Code': 403,
                    'Message': 'raising test exceptionParameter validation failed'
                    }
                }
            raise ParamValidationError(report=err)

        # Validate query keys
        for _, item_value in kwargs['RequestItems'].iteritems():
            if not item_value.get('Keys'):
                err = {'Error': {'Code': 400, 'Message': '[Keys] parameter is required'}}
                raise ParamValidationError(report=err)
            self._validate_keys(item_value['Keys'])

        response = {
            'UnprocessedKeys': {},
            'Responses': {
                'test_table_name': [
                    {
                        'ioc_value': {'S': '1.1.1.2'},
                        'sub_type': {'S': 'mal_ip'}
                    },
                    {
                        'ioc_value': {'S': 'evil.com'},
                        'sub_type': {'S': 'c2_domain'}
                    }
                ]
            },
            'ResponseMetadata': {
                'RetryAttempts': 0,
                'HTTPStatusCode': 200,
                'RequestId': 'ABCD1234',
                'HTTPHeaders': {}
            }
        }
        if self.has_unprocessed_keys:
            response['UnprocessedKeys'] = {
                'test_table_name': {
                    'Keys': [
                        {'ioc_value': {'S': 'foo'}},
                        {'ioc_value': {'S': 'bar'}}
                    ]
                }
            }

        return response

    @staticmethod
    def _validate_keys(dynamodb_data):
        """Helper method to check if query key empty or duplicated"""
        result = []
        if not dynamodb_data:
            err_msg = {'Error': {'Code': 403, 'Message': 'Empty query keys'}}
            raise ParamValidationError(report=err_msg)

        deserializer = TypeDeserializer()
        for raw_data in dynamodb_data:
            for _, val in raw_data.iteritems():
                python_data = deserializer.deserialize(val).lower()
                if not python_data or python_data in result:
                    err_msg = {'Error': {'Code': 403, 'Message': 'Parameter Validation Error'}}
                    raise ParamValidationError(report=err_msg)
                result.append(python_data)

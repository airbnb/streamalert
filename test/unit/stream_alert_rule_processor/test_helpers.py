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
import base64
import json

from mock import Mock

from stream_alert.rule_processor.classifier import StreamClassifier
from stream_alert.rule_processor.payload import load_stream_payload

from unit.stream_alert_rule_processor import (
    REGION,
    FUNCTION_NAME
)


class MultiprocProcessMock(object):
    """Mock class to house multiprocessing.Process mock methods"""

    def __init__(self, **kwargs):
        self.target = kwargs.get('target')
        self.args = kwargs.get('args')

    def start(self):
        """Mock 'start' method"""
        self.target(*self.args)

    def join(self):
        """Mock 'join' method"""
        pass


def _get_mock_context():
    """Create a fake context object using Mock"""
    arn = 'arn:aws:lambda:{}:123456789012:function:{}:development'
    context = Mock(invoked_function_arn=(arn.format(REGION, FUNCTION_NAME)),
                   function_name=FUNCTION_NAME)

    return context


def _get_valid_config():
    """Helper function to return a valid config for the rule processor. This
    simulates what stream_alert.rule_processor.load_config will return in a
    very simplified format.

    Returns:
        [dict] contents of a valid config file
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
        }
    }


def _get_valid_event(count=1):
    record_data = {
        'unit_key_01': '100',
        'unit_key_02': 'another bogus value'
    }

    data_json = json.dumps(record_data)
    raw_record = _make_kinesis_raw_record('unit_test_default_stream', data_json)

    return {'Records': [raw_record for _ in range(count)]}


def _load_and_classify_payload(config, service, entity, raw_record):

    # prepare the payloads
    payload = load_stream_payload(service, entity, raw_record, None)

    payload = payload.pre_parse().next()
    classifier = StreamClassifier(config=config)
    classifier.load_sources(service, entity)
    classifier.classify_record(payload)

    return payload


def _make_kinesis_raw_record(kinesis_stream, kinesis_data):
    """Helper for creating the kinesis raw record"""
    raw_record = {
        'eventID': 'unit test event id',
        'eventSource': 'aws:kinesis',
        'eventSourceARN': 'arn:aws:kinesis:us-east-1:123456789012:stream/{}'
                          .format(kinesis_stream),
        'kinesis': {
            'data': base64.b64encode(kinesis_data)
        }
    }
    return raw_record


def _make_sns_raw_record(topic_name, sns_data):
    """Helper for creating the sns raw record"""
    raw_record = {
        'EventSource': 'aws:kinesis',
        'EventSubscriptionArn': 'arn:aws:sns:us-east-1:123456789012:{}'
                                .format(topic_name),
        'Sns': {
            'MessageId': 'unit test message id',
            'Message': sns_data
        }
    }
    return raw_record


def _make_s3_raw_record(bucket, key):
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

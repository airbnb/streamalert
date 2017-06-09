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
import json

from mock import Mock

from unit.stream_alert_alert_processor import (
    REGION,
    FUNCTION_NAME
)

def _construct_event(count):
    """Helper to construct a valid test 'event' with an arbitrary number of records"""
    event = {'Records': []}
    for index in range(count):
        event['Records'] = event['Records'] + [{'Sns': {'Message': json.dumps(_get_alert(index))}}]

    return event

def _encrypt_with_kms(client, data):
    alias = 'alias/stream_alert_secrets_test'
    client.create_alias(AliasName=alias, TargetKeyId='1234abcd-12ab-34cd-56ef-1234567890ab')

    response = client.encrypt(KeyId=alias,
                              Plaintext=data)

    return response['CiphertextBlob']

def _get_alert(index):
    return {
        'default': {
            'record': {
                'test_index': index,
                'compressed_size': '9982',
                'timestamp': '1496947381.18',
                'node_id': '1',
                'cb_server': 'cbserver',
                'size': '21504',
                'type': 'binarystore.file.added',
                'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
                'md5': '0F9AA55DA3BDE84B35656AD8911A22E1'
            },
            'metadata': {
                'log': 'carbonblack:binarystore.file.added',
                'rule_name': 'cb_binarystore_file_added',
                'outputs': [
                    'slack:unit_test_channel'
                ],
                'source': {
                    'service': 's3',
                    'entity': 'corp-prefix.prod.cb.region'
                },
                'type': 'json',
                'rule_description': 'Info about this rule and what actions to take'
            }
        }
    }

def _get_mock_context():
    """Create a fake context object using Mock"""
    arn = 'arn:aws:lambda:{}:555555555555:function:{}:production'
    context = Mock(invoked_function_arn=(arn.format(REGION, FUNCTION_NAME)),
                   function_name='corp-prefix_prod_streamalert_alert_processor')

    return context

def _put_s3_test_object(client, bucket, key, data):
    client.create_bucket(Bucket=bucket)
    client.put_object(
        Body=data,
        Bucket=bucket,
        Key=key,
        ServerSideEncryption='AES256'
    )

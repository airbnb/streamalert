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

import boto3
from moto import mock_s3
from nose.tools import assert_equal

from stream_alert.rule_processor.pre_parsers import StreamPreParsers

BOTO_MOCKER = mock_s3()


def test_pre_parse_kinesis():
    """Pre-Parse Kinesis Test"""
    test_data = 'Hello world'
    raw_record = {'kinesis': {'data': base64.b64encode(test_data)}}
    data = StreamPreParsers.pre_parse_kinesis(raw_record)
    assert_equal(data, test_data)

def test_pre_parse_sns():
    """Pre-Parse SNS Test"""
    test_data = 'Hello world'
    raw_record = {'Sns': {'Message': base64.b64encode(test_data)}}
    data = StreamPreParsers.pre_parse_sns(raw_record)
    assert_equal(data, test_data)

def test_pre_parse_s3():
    """Pre-Parse S3 Test"""
    BOTO_MOCKER.start()
    region = 'us-east-1'
    bucket_name = 'test_bucket'
    key_name = 'test_key'
    body_value = 'this is a value for the object'
    raw_record = {
        'awsRegion': region,
        's3': {
            'bucket': {
                'name': bucket_name
            },
            'object': {
                'key': key_name,
                'size': 1000
            }
        }
    }

    s3_resource = boto3.resource('s3', region_name=region)
    s3_resource.create_bucket(Bucket=bucket_name)
    obj = s3_resource.Object(bucket_name, key_name)
    obj.put(Body=body_value)

    parsed = StreamPreParsers.pre_parse_s3(raw_record)
    assert_equal(body_value, parsed[0])

    BOTO_MOCKER.stop()

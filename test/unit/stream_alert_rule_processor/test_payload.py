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
import logging

from mock import call, Mock, patch

from nose.tools import (
    assert_equal,
    assert_false,
    assert_is_instance,
    assert_is_none,
    raises,
    with_setup
)

from stream_alert.rule_processor import LOGGER
from stream_alert.rule_processor.payload import (
    load_stream_payload,
    S3ObjectSizeError,
    S3Payload
)

from unit.stream_alert_rule_processor.test_helpers import (
    _make_kinesis_raw_record,
    _make_s3_raw_record,
    _make_sns_raw_record
)


def teardown_s3():
    """Tear down to reset class variable"""
    S3Payload.s3_object_size = 0


def test_load_payload_valid():
    """StreamPayload - Loading Stream Payload, Valid"""

    payload = load_stream_payload('s3', 'entity', 'record')

    assert_is_instance(payload, S3Payload)


@patch('logging.Logger.error')
def test_load_payload_invalid(log_mock):
    """StreamPayload - Loading Stream Payload, Invalid"""
    load_stream_payload('blah', 'entity', 'record')

    log_mock.assert_called_with('Service payload not supported: %s', 'blah')


def test_repr_string():
    """StreamPayload - String Representation"""
    s3_payload = load_stream_payload('s3', 'entity', 'record')

    # Set some values that are different than the defaults
    s3_payload.type = 'unit_type'
    s3_payload.log_source = 'unit_source'
    s3_payload.records = ['rec1', 'rec2']
    print_value = ('<S3Payload valid:False log_source:unit_source '
                   'entity:entity type:unit_type '
                   'record:[\'rec1\', \'rec2\']>')

    output_print = s3_payload.__repr__()
    assert_equal(output_print, print_value)


def test_get_service_kinesis():
    """StreamPayload - Get Service, Kinesis"""
    kinesis_payload = load_stream_payload('kinesis', 'entity', 'record')

    assert_equal(kinesis_payload.service(), 'kinesis')


def test_get_service_s3():
    """StreamPayload - Get Service, S3"""
    s3_payload = load_stream_payload('s3', 'entity', 'record')

    assert_equal(s3_payload.service(), 's3')


def test_get_service_sns():
    """StreamPayload - Get Service, SNS"""
    sns_payload = load_stream_payload('sns', 'entity', 'record')

    assert_equal(sns_payload.service(), 'sns')


def test_refresh_record():
    """StreamPayload - Refresh Record"""
    s3_payload = load_stream_payload('s3', 'entity', 'record')

    # Set some values that are different than the defaults
    s3_payload.type = 'unit_type'
    s3_payload.log_source = 'unit_source'
    s3_payload.records = ['rec1']
    s3_payload.valid = True

    s3_payload.refresh_record('new pre_parsed_record')

    assert_equal(s3_payload.pre_parsed_record, 'new pre_parsed_record')
    assert_is_none(s3_payload.type)
    assert_is_none(s3_payload.log_source)
    assert_is_none(s3_payload.records)
    assert_false(s3_payload.valid)


@patch('logging.Logger.debug')
def test_pre_parse_kinesis(log_mock):
    """KinesisPayload - Pre Parse"""
    kinesis_data = json.dumps({'test': 'value'})
    entity = 'unit_test_entity'
    raw_record = _make_kinesis_raw_record(entity, kinesis_data)
    kinesis_payload = load_stream_payload('kinesis', entity, raw_record)

    kinesis_payload = kinesis_payload.pre_parse().next()

    assert_equal(kinesis_payload.pre_parsed_record, '{"test": "value"}')

    log_mock.assert_called_with('Pre-parsing record from Kinesis. '
                                'eventID: %s, eventSourceARN: %s',
                                'unit test event id',
                                'arn:aws:kinesis:us-east-1:123456789012:stream/{}'
                                .format(entity))


@patch('logging.Logger.debug')
def test_pre_parse_sns(log_mock):
    """SNSPayload - Pre Parse"""
    sns_data = json.dumps({'test': 'value'})
    raw_record = _make_sns_raw_record('unit_topic', sns_data)
    sns_payload = load_stream_payload('sns', 'entity', raw_record)

    sns_payload = sns_payload.pre_parse().next()

    assert_equal(sns_payload.pre_parsed_record, '{"test": "value"}')

    log_mock.assert_called_with('Pre-parsing record from SNS. '
                                'MessageId: %s, EventSubscriptionArn: %s',
                                'unit test message id',
                                'arn:aws:sns:us-east-1:123456789012:unit_topic')


@patch('stream_alert.rule_processor.payload.S3Payload._get_object')
@patch('stream_alert.rule_processor.payload.S3Payload._read_s3_file')
def test_pre_parse_s3(s3_mock, __):
    """S3Payload - Pre Parse"""
    records = ['{"record01": "value01"}', '{"record02": "value02"}']
    s3_mock.side_effect = [((0, records[0]), (1, records[1]))]

    raw_record = _make_s3_raw_record('unit_bucket_name', 'unit_key_name')
    s3_payload = load_stream_payload('s3', 'unit_key_name', raw_record)

    for index, record in enumerate(s3_payload.pre_parse()):
        assert_equal(record.pre_parsed_record, records[index])


@with_setup(setup=None, teardown=teardown_s3)
@patch('stream_alert.rule_processor.payload.S3Payload._get_object')
@patch('logging.Logger.debug')
@patch('stream_alert.rule_processor.payload.S3Payload._read_s3_file')
def test_pre_parse_s3_debug(s3_mock, log_mock, _):
    """S3Payload - Pre Parse, Debug On"""
    # Cache the logger level
    lvl = LOGGER.getEffectiveLevel()

    # Increase the logger level to debug
    LOGGER.setLevel(logging.DEBUG)

    records = ['_first_line_test_' * 10,
               '_second_line_test_' * 10]

    s3_mock.side_effect = [((100, records[0]), (200, records[1]))]

    raw_record = _make_s3_raw_record('unit_bucket_name', 'unit_key_name')
    s3_payload = load_stream_payload('s3', 'unit_key_name', raw_record)
    S3Payload.s3_object_size = 350

    _ = [_ for _ in s3_payload.pre_parse()]

    calls = [call('Processed %s records out of an approximate total of %s '
                  '(average record size: %s bytes, total size: %s bytes)',
                  100, 350, 1, 350),
             call('Processed %s records out of an approximate total of %s '
                  '(average record size: %s bytes, total size: %s bytes)',
                  200, 350, 1, 350)
            ]

    log_mock.assert_has_calls(calls)

    # Reset the logger level and stop the patchers
    LOGGER.setLevel(lvl)


@with_setup(setup=None, teardown=teardown_s3)
@raises(S3ObjectSizeError)
def test_s3_object_too_large():
    """S3Payload - S3ObjectSizeError, Object too Large"""
    raw_record = _make_s3_raw_record('unit_bucket_name', 'unit_key_name')
    s3_payload = load_stream_payload('s3', 'unit_key_name', raw_record)
    S3Payload.s3_object_size = (128 * 1024 * 1024) + 10

    s3_payload._download_object('region', 'bucket', 'key')


@patch('stream_alert.rule_processor.payload.S3Payload._download_object')
@patch('logging.Logger.debug')
def test_get_object(log_mock, _):
    """S3Payload - Get S3 Info from Raw Record"""
    raw_record = _make_s3_raw_record('unit_bucket_name', 'unit_key_name')
    s3_payload = load_stream_payload('s3', 'unit_key_name', raw_record)

    s3_payload._get_object()
    log_mock.assert_called_with(
        'Pre-parsing record from S3. Bucket: %s, Key: %s, Size: %d',
        'unit_bucket_name', 'unit_key_name', 100
    )


@patch('logging.Logger.info')
@patch('stream_alert.rule_processor.payload.boto3.client')
@patch('stream_alert.rule_processor.payload.S3Payload._read_s3_file')
def test_s3_download_object(_, __, log_mock):
    """S3Payload - Download Object"""
    raw_record = _make_s3_raw_record('unit_bucket_name', 'unit_key_name')
    s3_payload = load_stream_payload('s3', 'unit_key_name', raw_record)
    s3_payload._download_object('us-east-1', 'unit_bucket_name', 'unit_key_name')

    assert_equal(log_mock.call_args_list[1][0][0], 'Completed download in %s seconds')


@with_setup(setup=None, teardown=teardown_s3)
@patch('logging.Logger.info')
@patch('stream_alert.rule_processor.payload.boto3.client')
@patch('stream_alert.rule_processor.payload.S3Payload._read_s3_file')
def test_s3_download_object_mb(_, __, log_mock):
    """S3Payload - Download Object, Size in MB"""
    raw_record = _make_s3_raw_record('unit_bucket_name', 'unit_key_name')
    s3_payload = load_stream_payload('s3', 'unit_key_name', raw_record)
    S3Payload.s3_object_size = (127.8 * 1024 * 1024)
    s3_payload._download_object('us-east-1', 'unit_bucket_name', 'unit_key_name')

    assert_equal(log_mock.call_args_list[0],
                 call('Starting download from S3: %s/%s [%s]',
                      'unit_bucket_name', 'unit_key_name', '127.8MB'))

    assert_equal(log_mock.call_args_list[1][0][0], 'Completed download in %s seconds')

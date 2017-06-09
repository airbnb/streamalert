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
import os
import urllib2

import boto3

from mock import patch, Mock

from moto import mock_s3, mock_kms
from nose.tools import assert_equal

from stream_alert.alert_processor.main import (
    _load_output_config as load_config,
    _sort_dict
)

from stream_alert.alert_processor.output_base import (
    OutputProperty,
    StreamOutputBase
)

from unit.stream_alert_alert_processor import (
    REGION,
    FUNCTION_NAME,
    CONFIG
)

from unit.stream_alert_alert_processor.helpers import (
    _encrypt_with_kms,
    _put_s3_test_object
)

# Remove all abstractmethods from __abstractmethods__ so we can
# instantiate StreamOutputBase for testing
StreamOutputBase.__abstractmethods__ = frozenset()
StreamOutputBase.__service__ = 'test_service'

def test_output_property_default():
    """OutputProperty defaults"""
    prop = OutputProperty()

    assert_equal(prop.description, '')
    assert_equal(prop.value, '')
    assert_equal(prop.input_restrictions, {' ', ':'})
    assert_equal(prop.mask_input, False)
    assert_equal(prop.cred_requirement, False)

def test_local_temp_dir():
    """Local Temp Dir"""
    temp_dir = StreamOutputBase(REGION, FUNCTION_NAME, CONFIG)._local_temp_dir()
    assert_equal(temp_dir.split('/')[-1], 'stream_alert_secrets')

def test_get_secrets_bucket_name():
    """Get Secrets Bucket Name"""
    bucket_name = StreamOutputBase(REGION, FUNCTION_NAME,
                                   CONFIG)._get_secrets_bucket_name(FUNCTION_NAME)
    assert_equal(bucket_name, 'corp-prefix.streamalert.secrets')

def test_output_cred_name():
    """Output Cred Name"""
    output_name = StreamOutputBase(REGION, FUNCTION_NAME,
                                   CONFIG).output_cred_name('creds')

    assert_equal(output_name, 'test_service/creds')

@mock_s3
def test_get_creds_from_s3():
    """Get Creds From S3"""
    descriptor = 'test_descriptor'
    test_data = 'credential test string'

    dispatcher = StreamOutputBase(REGION, FUNCTION_NAME, CONFIG)
    bucket_name = dispatcher.secrets_bucket
    key = dispatcher.output_cred_name(descriptor)

    local_cred_location = os.path.join(dispatcher._local_temp_dir(), key)

    client = boto3.client('s3', region_name=REGION)
    _put_s3_test_object(client, bucket_name, key, test_data)

    dispatcher._get_creds_from_s3(local_cred_location, descriptor)

    with open(local_cred_location) as creds:
        line = creds.readline()

    assert_equal(line, test_data)

@mock_kms
def test_kms_decrypt():
    """Credential KMS Decrypt"""
    test_data = 'data to encrypt'
    client = boto3.client('kms', region_name=REGION)

    encrypted = _encrypt_with_kms(client, test_data)
    decrypted = StreamOutputBase(REGION, FUNCTION_NAME, CONFIG)._kms_decrypt(encrypted)

    assert_equal(decrypted, test_data)


@patch('logging.Logger.info')
def test_log_status_failed(log_mock):
    """Log status success"""
    dispatcher = StreamOutputBase(REGION, FUNCTION_NAME, CONFIG)._log_status(True)
    log_mock.assert_called_with('successfully sent alert to %s', 'test_service')


@patch('logging.Logger.error')
def test_log_status_failed(log_mock):
    """Log status failed"""
    dispatcher = StreamOutputBase(REGION, FUNCTION_NAME, CONFIG)._log_status(False)
    log_mock.assert_called_with('failed to send alert to %s', 'test_service')


@patch('urllib2.urlopen')
def test_check_http_response(mock_getcode):
    """Check HTTP Response"""
    # Test with a good code
    mock_getcode.getcode.return_value = 200

    dispatcher = StreamOutputBase(REGION, FUNCTION_NAME, CONFIG)
    result = dispatcher._check_http_response(mock_getcode)

    assert_equal(result, True)

    # Test with a bad code
    mock_getcode.getcode.return_value = 440
    result = dispatcher._check_http_response(mock_getcode)

    assert_equal(result, False)

class TestFormatOutputConfig(object):
    """Test class for Output Config formatting"""
    __cached_name = StreamOutputBase.__service__
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        # Switch out the test service to one that is in the outputs.json file
        StreamOutputBase.__service__ = 'slack'

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        StreamOutputBase.__service__ = cls.__cached_name

    @staticmethod
    def test_format_output_config():
        """Format Output Config"""
        props = {'descriptor': OutputProperty('test_desc', 'test_channel')}

        formatted = StreamOutputBase(REGION, FUNCTION_NAME,
                                     CONFIG).format_output_config(CONFIG, props)

        assert_equal(len(formatted), 2)
        assert_equal(formatted[0], 'sample_channel')
        assert_equal(formatted[1], 'test_channel')

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
# pylint: disable=abstract-class-instantiated,protected-access
import os

from mock import patch
from moto import mock_kms, mock_s3
from nose.tools import assert_equal, assert_is_not_none

from stream_alert.alert_processor.output_base import OutputProperty, StreamOutputBase
from stream_alert_cli.helpers import encrypt_with_kms, put_mock_creds, put_mock_s3_object
from tests.unit.stream_alert_alert_processor import CONFIG, FUNCTION_NAME, KMS_ALIAS, REGION
from tests.unit.stream_alert_alert_processor.helpers import remove_temp_secrets

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


class TestStreamOutputBase(object):
    """Test class for StreamOutputBase

    Perform various tests for methods inherited by all output classes
    """
    __dispatcher = None
    __descriptor = 'desc_test'

    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.__dispatcher = StreamOutputBase(REGION, FUNCTION_NAME, CONFIG)

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.__dispatcher = None

    def test_local_temp_dir(self):
        """StreamOutputBase Local Temp Dir"""
        temp_dir = self.__dispatcher._local_temp_dir()
        assert_equal(temp_dir.split('/')[-1], 'stream_alert_secrets')

    def test_get_secrets_bucket_name(self):
        """StreamOutputBase Get Secrets Bucket Name"""
        bucket_name = self.__dispatcher._get_secrets_bucket_name(FUNCTION_NAME)
        assert_equal(bucket_name, 'corp-prefix.streamalert.secrets')

    def test_output_cred_name(self):
        """StreamOutputBase Output Cred Name"""
        output_name = self.__dispatcher.output_cred_name('creds')
        assert_equal(output_name, 'test_service/creds')

    @mock_s3
    def test_get_creds_from_s3(self):
        """StreamOutputBase Get Creds From S3"""
        descriptor = 'test_descriptor'
        test_data = 'credential test string'

        bucket_name = self.__dispatcher.secrets_bucket
        key = self.__dispatcher.output_cred_name(descriptor)

        local_cred_location = os.path.join(self.__dispatcher._local_temp_dir(), key)

        put_mock_s3_object(bucket_name, key, test_data, REGION)

        self.__dispatcher._get_creds_from_s3(local_cred_location, descriptor)

        with open(local_cred_location) as creds:
            line = creds.readline()

        assert_equal(line, test_data)

    @mock_kms
    def test_kms_decrypt(self):
        """StreamOutputBase KMS Decrypt"""
        test_data = 'data to encrypt'
        encrypted = encrypt_with_kms(test_data, REGION, KMS_ALIAS)
        decrypted = self.__dispatcher._kms_decrypt(encrypted)

        assert_equal(decrypted, test_data)

    @patch('logging.Logger.info')
    def test_log_status_success(self, log_mock):
        """StreamOutputBase Log status success"""
        self.__dispatcher._log_status(True)
        log_mock.assert_called_with('Successfully sent alert to %s', 'test_service')

    @patch('logging.Logger.error')
    def test_log_status_failed(self, log_mock):
        """StreamOutputBase Log status failed"""
        self.__dispatcher._log_status(False)
        log_mock.assert_called_with('Failed to send alert to %s', 'test_service')

    @patch('urllib2.urlopen')
    def test_check_http_response(self, mock_getcode):
        """StreamOutputBase Check HTTP Response"""
        # Test with a good response code
        mock_getcode.getcode.return_value = 200
        result = self.__dispatcher._check_http_response(mock_getcode)
        assert_equal(result, True)

        # Test with a bad response code
        mock_getcode.getcode.return_value = 440
        result = self.__dispatcher._check_http_response(mock_getcode)
        assert_equal(result, False)

    @mock_s3
    @mock_kms
    def test_load_creds(self):
        """Load Credentials"""
        remove_temp_secrets()
        output_name = self.__dispatcher.output_cred_name(self.__descriptor)

        creds = {'url': 'http://www.foo.bar/test',
                 'token': 'token_to_encrypt'}

        put_mock_creds(output_name, creds, self.__dispatcher.secrets_bucket, REGION, KMS_ALIAS)

        loaded_creds = self.__dispatcher._load_creds(self.__descriptor)

        assert_is_not_none(loaded_creds)
        assert_equal(len(loaded_creds), 2)
        assert_equal(loaded_creds['url'], u'http://www.foo.bar/test')
        assert_equal(loaded_creds['token'], u'token_to_encrypt')


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
        assert_equal(formatted[0], 'unit_test_channel')
        assert_equal(formatted[1], 'test_channel')

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
# pylint: disable=abstract-class-instantiated,protected-access,attribute-defined-outside-init
import json
import os
from collections import OrderedDict

from mock import Mock, patch, MagicMock
from moto import mock_kms, mock_s3
from nose.tools import (
    assert_true,
    assert_equal,
    assert_is_instance,
    assert_is_not_none,
    assert_is_none,
    assert_items_equal,
    assert_false)
from requests.exceptions import Timeout as ReqTimeout

from stream_alert.alert_processor.outputs.output_base import (
    OutputDispatcher,
    OutputProperty,
    OutputRequestFailure,
    StreamAlertOutput
)
from stream_alert.alert_processor.outputs.credentials.provider import (
    S3Driver,
    LocalFileDriver,
    Credentials,
    CredentialsProvidingDriver,
    OutputCredentialsProvider,
    EphemeralUnencryptedDriver, SpooledTempfileDriver)
from stream_alert.alert_processor.outputs.aws import S3Output
from stream_alert_cli.outputs.helpers import kms_encrypt
from tests.unit.stream_alert_alert_processor import (
    CONFIG,
    KMS_ALIAS,
    MOCK_ENV,
    REGION
)
from tests.unit.helpers.aws_mocks import put_mock_s3_object
from tests.unit.stream_alert_alert_processor.helpers import (
    encrypt_with_kms,
    put_mock_creds,
    remove_temp_secrets
)


class TestCredentials(object):

    @mock_kms
    def test_kms_decrypt(self):
        """Credentials - KMS Decrypt"""
        test_data = 'plaintext credentials'
        encrypted = encrypt_with_kms(test_data, REGION, KMS_ALIAS)

        credentials = Credentials(encrypted, True, REGION)

        assert_true(credentials.is_encrypted())

        decrypted = credentials.get_data_kms_decrypted()

        assert_equal(decrypted, test_data)


class TestOutputCredentialsProvider(object):

    @mock_s3
    @mock_kms
    def test_save_and_load_credentials(self):
        """OutputCredentials - Save and Load Credentials"""
        remove_temp_secrets()

        service_name = 'service'
        descriptor = 'descriptive'
        props = OrderedDict([
            ('property1',
             OutputProperty(description='This is a property and not a cred so it will not save')),
            ('property2',
             OutputProperty(description='Neither will this')),
            ('credential1',
             OutputProperty(description='Hello world',
                            value='this is a super secret secret, shhhh!',
                            mask_input=True,
                            cred_requirement=True)),
            ('credential2',
             OutputProperty(description='This appears too!',
                            value='where am i?',
                            mask_input=True,
                            cred_requirement=True)),
        ])
        defaults = {
            'property2': 'abcdef'
        }
        prefix = 'test_asdf'
        aws_account_id = '1234567890'

        # Pre-create the bucket so we dont get a "Bucket does not exist" error
        s3_driver = S3Driver(prefix, service_name, REGION)
        put_mock_s3_object(s3_driver.get_s3_secrets_bucket(), 'laskdjfaouhvawe', 'lafhawef', REGION)

        # Save credential
        provider = OutputCredentialsProvider(CONFIG, defaults, service_name, prefix, aws_account_id)
        provider.save_credentials(descriptor, KMS_ALIAS, props)

        # Pull it out
        creds_dict = provider.load_credentials(descriptor)
        expectation = {
            'property2': 'abcdef',
            'credential1': 'this is a super secret secret, shhhh!',
            'credential2': 'where am i?',
        }
        assert_equal(creds_dict, expectation)


#
# Tests for DRIVERS
#


class TestS3Driver(object):

    @mock_s3
    def test_load_credentials_plain_object(self):
        """S3Driver - Load String from S3

        In this test we save a simple string, unencrypted, into a mock S3 file. We use the
        driver to pull out this payload verbatim."""
        remove_temp_secrets()

        test_data = 'encrypted credential test string'
        descriptor = 'test_descriptor'

        s3_driver = S3Driver('rawr', 'service_name', REGION)

        # Stick some fake data into the credentials bucket file.
        bucket_name = s3_driver.get_s3_secrets_bucket()
        key = s3_driver.get_s3_key(descriptor)
        put_mock_s3_object(bucket_name, key, test_data, REGION)

        credentials = s3_driver.load_credentials(descriptor)

        # (!) Notably, in this test the credential contents are not encrypted when setup. They
        #     are supposed to be encrypted PRIOR to putting it in.
        assert_true(credentials.is_encrypted())
        assert_equal(credentials.data(), test_data)

    @mock_s3
    @mock_kms
    def test_load_credentials_encrypted_credentials(self):
        """S3Driver - Load Encrypted Credentials

        In this test we save a (more or less) real credentials payload using S3 mocking. We
        use the driver to pull the payload out and ensure the returned Credentials object is
        in a stable state, and that we can retrieve the decrypt credentials from this object."""

        # In this test we use put_mock_creds() to save an encrypted credentials
        remove_temp_secrets()

        descriptor = 'test_descriptor'
        driver = S3Driver('test_prefix', 'test_service', REGION)

        bucket = driver.get_s3_secrets_bucket()
        key = driver.get_s3_key(descriptor)

        creds = {'url': 'http://www.foo.bar/test',
                 'token': 'token_to_encrypt'}

        put_mock_creds(key, creds, bucket, REGION, KMS_ALIAS)  # This encrypts the contents

        credentials = driver.load_credentials(descriptor)

        assert_is_not_none(credentials)
        assert_true(credentials.is_encrypted())

        loaded_creds = json.loads(credentials.get_data_kms_decrypted())

        assert_equal(len(loaded_creds), 2)
        assert_equal(loaded_creds['url'], u'http://www.foo.bar/test')
        assert_equal(loaded_creds['token'], u'token_to_encrypt')

    def test_has_credentials(self):
        """S3Driver - Has Credentials

        Not much of a test; we assume that S3 always has the credentials.
        """
        s3_driver = S3Driver('prefix', 'service_name', 'region')
        assert_true(s3_driver.has_credentials('some_descriptor'))

    @mock_s3
    @mock_kms
    def test_save_credentials(self):
        """S3Driver - Save Credentials

        We test a full cycle of using save_credentials() then subsequently pulling them out with
        load_credentials()."""
        remove_temp_secrets()

        creds = {'url': 'http://best.website.ever/test'}
        input_credentials = Credentials(creds, False, REGION)
        descriptor = 'test_descriptor'
        driver = S3Driver('test_prefix', 'test_service', REGION)

        # Annoyingly, moto needs us to create the bucket first
        # We put a random unrelated object into the bucket and this will set up the bucket for us
        put_mock_s3_object(driver.get_s3_secrets_bucket(), 'laskdjfaouhvawe', 'lafhawef', REGION)

        result = driver.save_credentials(descriptor, input_credentials, KMS_ALIAS)
        assert_true(result)

        credentials = driver.load_credentials(descriptor)

        assert_is_not_none(credentials)
        assert_true(credentials.is_encrypted())

        loaded_creds = json.loads(credentials.get_data_kms_decrypted())

        assert_equal(loaded_creds, creds)

    def test_get_s3_secrets_bucket(self):
        """S3Driver - Get S3 Secrets Bucket Name"""
        s3_driver = S3Driver('rawr', 'service_name', 'region')
        assert_equal(s3_driver.get_s3_secrets_bucket(), 'rawr.streamalert.secrets')

    @mock_s3
    @mock_kms
    def test_load_credentials_pulls_into_local_cache(self):
        """S3Driver - Load Credentials - Pulls into LocalFileStore

        Here we use the S3Driver's caching ability to yank stuff into a local driver."""
        remove_temp_secrets()

        creds = {'my_secret': 'i ate two portions of biscuits and gravy'}
        input_credentials = Credentials(creds, False, REGION)
        service_name = 'test_service'
        descriptor = 'test_descriptor'
        fs_driver = LocalFileDriver(REGION, service_name)
        s3_driver = S3Driver('test_prefix', service_name, REGION, fs_driver)

        # Annoyingly, moto needs us to create the bucket first
        # We put a random unrelated object into the bucket and this will set up the bucket for us
        put_mock_s3_object(s3_driver.get_s3_secrets_bucket(), 'laskdjfaouhvawe', 'lafhawef', REGION)

        # First, check if the Local driver can find the credentials (we don't expect it to)
        assert_false(fs_driver.has_credentials(descriptor))

        # Save the credentials using S3 driver
        result = s3_driver.save_credentials(descriptor, input_credentials, KMS_ALIAS)
        assert_true(result)

        # We still don't expect the Local driver to find the credentials
        assert_false(fs_driver.has_credentials(descriptor))

        # Use S3Driver to warm up the Local driver
        s3_driver.load_credentials(descriptor)

        # Now we should be able to get the credentials from the local fs
        assert_true(fs_driver.has_credentials(descriptor))
        credentials = fs_driver.load_credentials(descriptor)

        assert_is_not_none(credentials)
        assert_true(credentials.is_encrypted())

        loaded_creds = json.loads(credentials.get_data_kms_decrypted())

        assert_equal(loaded_creds, creds)

        remove_temp_secrets()


class TestLocalFileDriver(object):

    def setup(self):
        LocalFileDriver.clear()

    def teardown(self):
        LocalFileDriver.clear()

    def test_get_load_credentials_temp_dir(self):
        """LocalFileDriver - Get Load Credentials Temp Dir"""
        temp_dir = LocalFileDriver.get_local_credentials_temp_dir()
        assert_equal(temp_dir.split('/')[-1], 'stream_alert_secrets')

    def test_get_formatted_output_credentials_name(self):
        """LocalFileDriver - Get Formatted Output Credentials Name"""
        name = LocalFileDriver.get_formatted_output_credentials_name(
            'test_service_name',
            'test_descriptor'
        )
        assert_equal(name, 'test_service_name/test_descriptor')

    def test_get_formatted_output_credentials_name_no_descriptor(self): #pylint: disable=invalid-name
        """LocalFileDriver - Get Formatted Output Credentials Name - No Descriptor"""
        name = LocalFileDriver.get_formatted_output_credentials_name(
            'test_service_name',
            ''
        )
        assert_equal(name, 'test_service_name')

    def test_save_and_has_credentials(self):
        """LocalFileDriver - Save and Has Credentials"""
        driver = LocalFileDriver(REGION, 'service')
        assert_false(driver.has_credentials('descriptor'))

        credentials = Credentials('aaaa', True)  # pretend it's encrypted
        driver.save_credentials('descriptor', credentials)

        assert_true(driver.has_credentials('descriptor'))

    @mock_kms
    def test_save_and_load_credentials(self):
        """LocalFileDriver - Save and Load Credentials"""
        raw_credentials = 'aaaa'
        descriptor = 'descriptor'
        service_name = 'test_service'
        driver = LocalFileDriver(REGION, service_name)

        encrypted_raw_credentials = kms_encrypt(REGION, raw_credentials, KMS_ALIAS)

        credentials = Credentials(encrypted_raw_credentials, True, REGION)
        assert_true(driver.save_credentials(descriptor, credentials))

        loaded_credentials = driver.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_true(loaded_credentials.is_encrypted())
        assert_equal(loaded_credentials.get_data_kms_decrypted(), raw_credentials)

    @mock_kms
    def test_save_and_load_credentials_persists_statically(self):
        """LocalFileDriver - Save and Load Credentials"""
        raw_credentials = 'aaaa'
        descriptor = 'descriptor'
        service_name = 'test_service'
        driver = LocalFileDriver(REGION, service_name)

        encrypted_raw_credentials = kms_encrypt(REGION, raw_credentials, KMS_ALIAS)

        credentials = Credentials(encrypted_raw_credentials, True, REGION)
        assert_true(driver.save_credentials(descriptor, credentials))

        driver2 = LocalFileDriver(REGION, service_name)
        loaded_credentials = driver2.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_true(loaded_credentials.is_encrypted())
        assert_equal(loaded_credentials.get_data_kms_decrypted(), raw_credentials)

    def test_save_errors_on_unencrypted(self):
        """LocalFileDriver - Save Errors on Unencrypted Credentials"""
        raw_credentials_dict = {
            'python': 'is very difficult',
            'someone': 'save meeeee',
        }
        descriptor = 'descriptor5'
        service_name = 'test_service'

        raw_credentials = json.dumps(raw_credentials_dict)

        credentials = Credentials(raw_credentials, False, REGION)
        driver = LocalFileDriver(REGION, service_name)

        assert_false(driver.save_credentials(descriptor, credentials))
        assert_false(driver.has_credentials(descriptor))

    def test_clear(self):
        """LocalFileDriver - Clear Credentials"""
        descriptor = 'descriptor'
        service_name = 'test_service'
        driver = LocalFileDriver(REGION, service_name)

        credentials = Credentials('aaaa', True, REGION)  # pretend it's encrypted
        driver.save_credentials(descriptor, credentials)

        driver2 = LocalFileDriver(REGION, service_name)
        assert_true(driver2.has_credentials(descriptor))

        LocalFileDriver.clear()

        assert_false(driver2.has_credentials(descriptor))


class TestSpooledTempfileDriver(object):

    def setup(self):
        SpooledTempfileDriver.clear()

    def teardown(self):
        SpooledTempfileDriver.clear()

    def test_save_and_has_credentials(self):
        """SpooledTempfileDriver - Save and Has Credentials"""
        driver = SpooledTempfileDriver('service', REGION)
        assert_false(driver.has_credentials('descriptor'))

        credentials = Credentials('aaaa', True)  # let's pretend they're encrypted
        assert_true(driver.save_credentials('descriptor', credentials))

        assert_true(driver.has_credentials('descriptor'))

    @mock_kms
    def test_save_and_load_credentials(self):
        """SpooledTempfileDriver - Save and Load Credentials"""
        raw_credentials = 'aaaa'
        descriptor = 'descriptor'
        service_name = 'test_service'
        driver = SpooledTempfileDriver(service_name, REGION)

        encrypted_raw_credentials = kms_encrypt(REGION, raw_credentials, KMS_ALIAS)

        credentials = Credentials(encrypted_raw_credentials, True, REGION)
        assert_true(driver.save_credentials(descriptor, credentials))

        loaded_credentials = driver.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_true(loaded_credentials.is_encrypted())
        assert_equal(loaded_credentials.get_data_kms_decrypted(), raw_credentials)

    @mock_kms
    def test_save_and_load_credentials_persists_statically(self):
        """SpooledTempfileDriver - Save and Load Credentials"""
        raw_credentials_dict = {
            'python': 'is very difficult',
            'someone': 'save meeeee',
        }
        descriptor = 'descriptor'
        service_name = 'test_service'
        driver = SpooledTempfileDriver(service_name, REGION)

        raw_credentials = json.dumps(raw_credentials_dict)
        encrypted_raw_credentials = kms_encrypt(REGION, raw_credentials, KMS_ALIAS)

        credentials = Credentials(encrypted_raw_credentials, True)
        assert_true(driver.save_credentials(descriptor, credentials))

        driver2 = SpooledTempfileDriver(service_name, REGION)
        loaded_credentials = driver2.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_true(loaded_credentials.is_encrypted())
        assert_equal(loaded_credentials.get_data_kms_decrypted(), raw_credentials)

    def test_save_errors_on_unencrypted(self):
        """SpooledTempfileDriver - Save Errors on Unencrypted Credentials"""
        raw_credentials = 'aaaa'
        descriptor = 'descriptor5'
        service_name = 'test_service'

        credentials = Credentials(raw_credentials, False)
        driver = SpooledTempfileDriver(service_name, REGION)

        assert_false(driver.save_credentials(descriptor, credentials))
        assert_false(driver.has_credentials(descriptor))

    def test_clear(self):
        """SpooledTempfileDriver - Clear Credentials"""
        descriptor = 'descriptor'
        service_name = 'test_service'
        driver = SpooledTempfileDriver(service_name, REGION)

        credentials = Credentials('aaaa', True)  # pretend it's encrypted
        assert_true(driver.save_credentials(descriptor, credentials))

        driver2 = SpooledTempfileDriver(service_name, REGION)
        assert_true(driver2.has_credentials(descriptor))

        SpooledTempfileDriver.clear()

        assert_false(driver2.has_credentials(descriptor))


class TestEphemeralUnencryptedDriver(object):

    def setup(self):
        EphemeralUnencryptedDriver.clear()

    def teardown(self):
        EphemeralUnencryptedDriver.clear()

    def test_save_and_has_credentials(self):
        """EphemeralUnencryptedDriver - Save and Has Credentials"""
        driver = EphemeralUnencryptedDriver('service')
        assert_false(driver.has_credentials('descriptor'))

        credentials = Credentials('aaaa', False)
        assert_true(driver.save_credentials('descriptor', credentials))

        assert_true(driver.has_credentials('descriptor'))

    def test_save_and_load_credentials(self):
        """EphemeralUnencryptedDriver - Save and Load Credentials"""
        descriptor = 'descriptor'
        service_name = 'test_service'
        driver = EphemeralUnencryptedDriver(service_name)

        credentials = Credentials('aaaa', False)
        assert_true(driver.save_credentials(descriptor, credentials))

        loaded_credentials = driver.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_false(loaded_credentials.is_encrypted())
        assert_equal(loaded_credentials.data(), 'aaaa')

    def test_save_and_load_credentials_persists_statically(self):
        """EphemeralUnencryptedDriver - Save and Load Credentials"""
        descriptor = 'descriptor'
        service_name = 'test_service'
        driver = EphemeralUnencryptedDriver(service_name)

        credentials = Credentials('aaaa', False)
        assert_true(driver.save_credentials(descriptor, credentials))

        driver2 = EphemeralUnencryptedDriver(service_name)
        loaded_credentials = driver2.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_false(loaded_credentials.is_encrypted())
        assert_equal(loaded_credentials.data(), 'aaaa')

    @mock_kms
    def test_save_automatically_decrypts(self):
        """EphemeralUnencryptedDriver - Save Automatically Decrypts"""
        raw_credentials_dict = {
            'python': 'is very difficult',
            'someone': 'save meeeee',
        }
        descriptor = 'descriptor5'
        service_name = 'test_service'

        raw_credentials = json.dumps(raw_credentials_dict)
        encrypted_raw_credentials = kms_encrypt(REGION, raw_credentials, KMS_ALIAS)

        credentials = Credentials(encrypted_raw_credentials, True, REGION)
        driver = EphemeralUnencryptedDriver(service_name)

        assert_true(driver.save_credentials(descriptor, credentials))

        driver2 = EphemeralUnencryptedDriver(service_name)
        loaded_credentials = driver2.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_false(loaded_credentials.is_encrypted())
        assert_equal(json.loads(loaded_credentials.data()), raw_credentials_dict)

    def test_clear(self):
        """EphemeralUnencryptedDriver - Clear Credentials"""
        descriptor = 'descriptor'
        service_name = 'test_service'
        driver = EphemeralUnencryptedDriver(service_name)

        credentials = Credentials('aaaa', False)
        driver.save_credentials(descriptor, credentials)

        driver2 = EphemeralUnencryptedDriver(service_name)
        assert_true(driver2.has_credentials(descriptor))

        EphemeralUnencryptedDriver.clear()

        assert_false(driver2.has_credentials(descriptor))

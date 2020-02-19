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

from botocore.exceptions import ClientError
from mock import patch, MagicMock
from moto import mock_kms, mock_s3
from nose.tools import (
    assert_true,
    assert_equal,
    assert_is_instance,
    assert_is_not_none,
    assert_false,
    assert_is_none,
)

from streamalert.alert_processor.outputs.output_base import OutputProperty
from streamalert.alert_processor.outputs.credentials.provider import (
    S3Driver,
    LocalFileDriver,
    Credentials,
    OutputCredentialsProvider,
    EphemeralUnencryptedDriver, SpooledTempfileDriver, get_formatted_output_credentials_name)
from tests.unit.streamalert.alert_processor import (
    CONFIG,
    KMS_ALIAS,
    REGION,
    MOCK_ENV
)
from tests.unit.helpers.aws_mocks import put_mock_s3_object
from tests.unit.streamalert.alert_processor.helpers import (
    encrypt_with_kms,
    put_mock_creds,
    remove_temp_secrets
)


#
# class Credentials Tests
#


class TestCredentialsEncrypted:
    @mock_kms
    def setup(self):
        self._plaintext_payload = 'plaintext credentials'
        self._encrypted_payload = encrypt_with_kms(self._plaintext_payload, REGION, KMS_ALIAS)
        self._credentials = Credentials(self._encrypted_payload, is_encrypted=True, region=REGION)

    def test_is_encrypted(self):
        """Credentials - Encrypted Credentials - Is Encrypted"""
        assert_true(self._credentials.is_encrypted())

    def test_is_data(self):
        """Credentials - Encrypted Credentials - Data"""
        assert_equal(self._credentials.data(), self._encrypted_payload)

    @mock_kms
    def test_get_data_kms_decrypted(self):
        """Credentials - Encrypted Credentials - KMS Decrypt"""
        decrypted = self._credentials.get_data_kms_decrypted()
        assert_equal(decrypted, self._plaintext_payload.encode())

    def test_encrypt(self):
        """Credentials - Encrypted Credentials - Encrypt

        Doubly-encrypting the credentials should do nothing.
        """
        self._credentials.encrypt(REGION, KMS_ALIAS)
        assert_equal(self._credentials.data(), self._encrypted_payload)

    @patch('boto3.client')
    @patch('logging.Logger.exception')
    def test_decrypt_kms_error(self, logging_exception, boto3):
        """Credentials - Encrypted Credentials - KMS Decrypt - Errors if KMS Fails to Respond"""

        # We pretend that KMS errors out
        boto3_client = MagicMock()
        boto3.return_value = boto3_client

        response = MagicMock()
        boto3_client.decrypt.side_effect = ClientError(response, 'kms_decrypt')

        assert_is_none(self._credentials.get_data_kms_decrypted())
        logging_exception.assert_called_with('an error occurred during credentials decryption')


class TestCredentialsUnencrypted:
    def setup(self):
        self._plaintext_payload = 'plaintext credentials'
        self._credentials = Credentials(self._plaintext_payload, is_encrypted=False)

    def test_is_encrypted(self):
        """Credentials - Plaintext Credentials - Is Encrypted"""
        assert_false(self._credentials.is_encrypted())

    def test_is_data(self):
        """Credentials - Plaintext Credentials - Data"""
        assert_equal(self._credentials.data(), self._plaintext_payload)

    @patch('logging.Logger.error')
    def test_get_data_kms_decrypted(self, logging_error):
        """Credentials - Plaintext Credentials - KMS Decrypt"""
        assert_is_none(self._credentials.get_data_kms_decrypted())
        logging_error.assert_called_with('Cannot decrypt Credentials as they are already decrypted')

    @mock_kms
    def test_encrypt(self):
        """Credentials - Plaintext Credentials - Encrypt

        Doubly-encrypting the credentials should do nothing.
        """
        self._credentials.encrypt(REGION, KMS_ALIAS)

        assert_true(self._credentials.is_encrypted())
        assert_equal(self._credentials.data(), 'InBsYWludGV4dCBjcmVkZW50aWFscyI='.encode())


class TestCredentialsEmpty:
    def setup(self):
        self._plaintext_payload = ''
        self._credentials = Credentials(self._plaintext_payload, is_encrypted=False)

    @mock_kms
    def test_encrypt(self):
        """Credentials - Empty Credentials - Encrypt - Does nothing when payload is empty"""
        self._credentials.encrypt(REGION, KMS_ALIAS)

        assert_true(self._credentials.is_encrypted())
        assert_equal(self._credentials.data(), '')


#
# class OutputCredentialsProvider Tests
#


@patch.dict(os.environ, MOCK_ENV)
def test_constructor_loads_from_os_when_not_provided():
    """OutputCredentials - Constructor

    When not provided, prefix and aws account id are loaded from the OS Environment."""

    provider = OutputCredentialsProvider('that_service_name', config=CONFIG, region=REGION)
    assert_equal(provider._prefix, 'prefix')
    assert_equal(provider.get_aws_account_id(), '123456789012')


@mock_s3
class TestOutputCredentialsProvider:
    def setup(self):
        service_name = 'service'
        defaults = {
            'property2': 'abcdef'
        }
        prefix = 'test_asdf'
        aws_account_id = '1234567890'

        self._provider = OutputCredentialsProvider(
            service_name,
            config=CONFIG,
            defaults=defaults,
            region=REGION,
            prefix=prefix,
            aws_account_id=aws_account_id
        )

        # Pre-create the bucket so we dont get a "Bucket does not exist" error
        s3_driver = S3Driver('test_asdf', 'service', REGION)
        put_mock_s3_object(s3_driver.get_s3_secrets_bucket(), 'laskdjfaouhvawe', 'lafhawef', REGION)

    @mock_kms
    def test_save_and_load_credentials(self):
        """OutputCredentials - Save and Load Credentials

        Not only tests how save_credentials() interacts with load_credentials(), but also tests
        that cred_requirement=False properties are not saved. Also tests that default values
        are merged into the final credentials dict as appropriate."""

        descriptor = 'test_save_and_load_credentials'
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

        # Save credential
        assert_true(self._provider.save_credentials(descriptor, KMS_ALIAS, props))

        # Pull it out
        creds_dict = self._provider.load_credentials(descriptor)
        expectation = {
            'property2': 'abcdef',
            'credential1': 'this is a super secret secret, shhhh!',
            'credential2': 'where am i?',
        }
        assert_equal(creds_dict, expectation)

    @mock_kms
    def test_load_credentials_multiple(self):
        """OutputCredentials - Load Credentials Loads from Cache Driver

        This test ensures that we only hit S3 once during, and that subsequent calls are routed
        to the Cache driver. Currently the cache driver is configured as Ephemeral."""

        descriptor = 'test_load_credentials_pulls_from_cache'
        props = OrderedDict([
            ('credential1',
             OutputProperty(description='Hello world',
                            value='there is no cow level',
                            mask_input=True,
                            cred_requirement=True)),
        ])

        # Save credential
        self._provider.save_credentials(descriptor, KMS_ALIAS, props)

        # Pull it out (Normal expected behavior)
        creds_dict = self._provider.load_credentials(descriptor)
        expectation = {'credential1': 'there is no cow level', 'property2': 'abcdef'}
        assert_equal(creds_dict, expectation)

        # Now we yank the S3 driver out of the driver pool
        # FIXME (derek.wang): Another way to do this is to install a spy on moto and make assertions
        #                     on the number of times it is called.
        assert_is_instance(self._provider._drivers[1], S3Driver)
        self._provider._drivers[1] = None
        self._provider._core_driver = None

        # Load again and see if it still is able to load without S3
        assert_equal(self._provider.load_credentials(descriptor), expectation)

        # Double-check; Examine the Driver guts and make sure that the EphemeralDriver has the
        # value cached.
        ep_driver = self._provider._drivers[0]
        assert_is_instance(ep_driver, EphemeralUnencryptedDriver)

        assert_true(ep_driver.has_credentials(descriptor))
        creds = ep_driver.load_credentials(descriptor)
        assert_equal(json.loads(creds.data())['credential1'], 'there is no cow level')

    @patch('logging.Logger.error')
    def test_load_credentials_returns_none_on_driver_failure(self, logging_error): #pylint: disable=invalid-name
        """OutputCredentials - Load Credentials Returns None on Driver Failure"""
        descriptor = 'descriptive'

        # To pretend all drivers fail, we can just remove all of the drivers.
        self._provider._drivers = []
        self._provider._core_driver = None

        creds_dict = self._provider.load_credentials(descriptor)
        assert_is_none(creds_dict)
        logging_error.assert_called_with('All drivers failed to retrieve credentials for [%s.%s]',
                                         'service',
                                         descriptor)

#
# Tests for S3Driver
#


class TestS3Driver:
    def setup(self):
        self._s3_driver = S3Driver('rawr', 'service_name', REGION)

    @patch('boto3.client')
    @patch('logging.Logger.exception')
    def test_load_credentials_s3_failure(self, logging_exception, boto3):
        """S3Driver - Load String returns None on S3 Failure"""
        descriptor = 'test_descriptor'

        # Pretend S3 fails to respond
        boto3_client = MagicMock()
        boto3.return_value = boto3_client
        response = MagicMock()
        boto3_client.download_fileobj.side_effect = ClientError(response, 's3_download_fileobj')

        assert_is_none(self._s3_driver.load_credentials(descriptor))
        logging_exception.assert_called_with(
            "credentials for '%s' could not be downloaded from S3",
            'service_name/test_descriptor'
        )

    @mock_s3
    def test_load_credentials_plain_object(self):
        """S3Driver - Load String from S3

        In this test we save a simple string, unencrypted, into a mock S3 file. We use the
        driver to pull out this payload verbatim."""
        test_data = 'encrypted credential test string'
        descriptor = 'test_descriptor'

        # Stick some fake data into the credentials bucket file.
        bucket_name = self._s3_driver.get_s3_secrets_bucket()
        key = self._s3_driver.get_s3_key(descriptor)
        put_mock_s3_object(bucket_name, key, test_data, REGION)

        credentials = self._s3_driver.load_credentials(descriptor)

        # (!) Notably, in this test the credential contents are not encrypted when setup. They
        #     are supposed to be encrypted PRIOR to putting it in.
        assert_true(credentials.is_encrypted())
        assert_equal(credentials.data(), test_data.encode())

    @mock_s3
    @mock_kms
    def test_load_credentials_encrypted_credentials(self):
        """S3Driver - Load Encrypted Credentials

        In this test we save a (more or less) real credentials payload using S3 mocking. We
        use the driver to pull the payload out and ensure the returned Credentials object is
        in a stable state, and that we can retrieve the decrypt credentials from this object."""
        descriptor = 'test_descriptor'

        bucket = self._s3_driver.get_s3_secrets_bucket()
        key = self._s3_driver.get_s3_key(descriptor)

        creds = {'url': 'http://www.foo.bar/test',
                 'token': 'token_to_encrypt'}

        # Save encrypted credentials
        put_mock_creds(key, creds, bucket, REGION, KMS_ALIAS)

        credentials = self._s3_driver.load_credentials(descriptor)

        assert_is_not_none(credentials)
        assert_true(credentials.is_encrypted())

        loaded_creds = json.loads(credentials.get_data_kms_decrypted())

        assert_equal(len(loaded_creds), 2)
        assert_equal(loaded_creds['url'], 'http://www.foo.bar/test')
        assert_equal(loaded_creds['token'], 'token_to_encrypt')

    def test_has_credentials(self):
        """S3Driver - Has Credentials

        Not much of a test; we assume that S3 always has the credentials.
        """
        assert_true(self._s3_driver.has_credentials('some_descriptor'))

    @mock_s3
    @mock_kms
    def test_save_credentials_into_s3(self):
        """S3Driver - Save Credentials

        We test a full cycle of using save_credentials() then subsequently pulling them out with
        load_credentials()."""
        creds = {'url': 'http://best.website.ever/test'}
        input_credentials = Credentials(creds, is_encrypted=False, region=REGION)
        descriptor = 'test_descriptor'

        # Annoyingly, moto needs us to create the bucket first
        # We put a random unrelated object into the bucket and this will set up the bucket for us
        put_mock_s3_object(self._s3_driver.get_s3_secrets_bucket(), 'aaa', 'bbb', REGION)

        result = self._s3_driver.save_credentials_into_s3(descriptor, input_credentials, KMS_ALIAS)
        assert_true(result)

        credentials = self._s3_driver.load_credentials(descriptor)

        assert_is_not_none(credentials)
        assert_true(credentials.is_encrypted())

        loaded_creds = json.loads(credentials.get_data_kms_decrypted())

        assert_equal(loaded_creds, creds)

    @mock_s3
    def test_save_credentials_into_s3_blank_credentials(self):
        """S3Driver - Save Credentials does nothing when Credentials are Blank"""
        input_credentials = Credentials('', is_encrypted=False, region=REGION)
        descriptor = 'test_descriptor22'

        result = self._s3_driver.save_credentials_into_s3(descriptor, input_credentials, KMS_ALIAS)
        assert_true(result)

        assert_is_none(self._s3_driver.load_credentials(descriptor))

    def test_get_s3_secrets_bucket(self):
        """S3Driver - Get S3 Secrets Bucket Name"""
        assert_equal(self._s3_driver.get_s3_secrets_bucket(), 'rawr-streamalert-secrets')


class TestS3DriverWithFileDriver:
    def setup(self):
        service_name = 'test_service'
        self._fs_driver = LocalFileDriver(REGION, service_name)
        self._s3_driver = S3Driver('test_prefix', service_name, REGION, file_driver=self._fs_driver)

    @mock_s3
    @mock_kms
    def test_load_credentials(self):
        """S3Driver - With File Driver - Load Credentials - Pulls into LocalFileStore

        Here we use the S3Driver's caching ability to yank stuff into a local driver."""
        remove_temp_secrets()

        creds = {'my_secret': 'i ate two portions of biscuits and gravy'}
        input_credentials = Credentials(creds, is_encrypted=False, region=REGION)
        descriptor = 'test_descriptor'

        # Annoyingly, moto needs us to create the bucket first
        # We put a random unrelated object into the bucket and this will set up the bucket for us
        put_mock_s3_object(self._s3_driver.get_s3_secrets_bucket(), 'aaa', 'bbb', REGION)

        # First, check if the Local driver can find the credentials (we don't expect it to)
        assert_false(self._fs_driver.has_credentials(descriptor))

        # Save the credentials using S3 driver
        result = self._s3_driver.save_credentials_into_s3(descriptor, input_credentials, KMS_ALIAS)
        assert_true(result)

        # We still don't expect the Local driver to find the credentials
        assert_false(self._fs_driver.has_credentials(descriptor))

        # Use S3Driver to warm up the Local driver
        self._s3_driver.load_credentials(descriptor)

        # Now we should be able to get the credentials from the local fs
        assert_true(self._fs_driver.has_credentials(descriptor))
        credentials = self._fs_driver.load_credentials(descriptor)

        assert_is_not_none(credentials)
        assert_true(credentials.is_encrypted())

        loaded_creds = json.loads(credentials.get_data_kms_decrypted())

        assert_equal(loaded_creds, creds)

        remove_temp_secrets()


#
# class LocalFileDriver Tests
#


def test_get_formatted_output_credentials_name():
    """LocalFileDriver - Get Formatted Output Credentials Name"""
    name = get_formatted_output_credentials_name(
        'test_service_name',
        'test_descriptor'
    )
    assert_equal(name, 'test_service_name/test_descriptor')


def test_get_load_credentials_temp_dir():
    """LocalFileDriver - Get Load Credentials Temp Dir"""
    temp_dir = LocalFileDriver.get_local_credentials_temp_dir()
    assert_equal(temp_dir.split('/')[-1], 'streamalert_secrets')


def test_get_formatted_output_credentials_name_no_descriptor(): #pylint: disable=invalid-name
    """LocalFileDriver - Get Formatted Output Credentials Name - No Descriptor"""
    name = get_formatted_output_credentials_name(
        'test_service_name',
        ''
    )
    assert_equal(name, 'test_service_name')


class TestLocalFileDriver:

    def setup(self):
        LocalFileDriver.clear()
        self._fs_driver = LocalFileDriver(REGION, 'service')

    @staticmethod
    def teardown():
        LocalFileDriver.clear()

    def test_save_and_has_credentials(self):
        """LocalFileDriver - Save and Has Credentials"""
        assert_false(self._fs_driver.has_credentials('descriptor'))

        credentials = Credentials('aaaa', True)  # pretend it's encrypted
        self._fs_driver.save_credentials('descriptor', credentials)

        assert_true(self._fs_driver.has_credentials('descriptor'))

    @mock_kms
    def test_save_and_load_credentials(self):
        """LocalFileDriver - Save and Load Credentials"""
        raw_credentials = 'aaaa'
        descriptor = 'descriptor'

        encrypted_raw_credentials = encrypt_with_kms(raw_credentials, REGION, KMS_ALIAS)

        credentials = Credentials(encrypted_raw_credentials, True, REGION)
        assert_true(self._fs_driver.save_credentials(descriptor, credentials))

        loaded_credentials = self._fs_driver.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_true(loaded_credentials.is_encrypted())
        assert_equal(loaded_credentials.get_data_kms_decrypted(), raw_credentials.encode())

    @mock_kms
    def test_save_and_load_credentials_persists_statically(self):
        """LocalFileDriver - Save and Load Credentials"""
        raw_credentials = 'aaaa'
        descriptor = 'descriptor'

        encrypted_raw_credentials = encrypt_with_kms(raw_credentials, REGION, KMS_ALIAS)

        credentials = Credentials(encrypted_raw_credentials, True, REGION)
        assert_true(self._fs_driver.save_credentials(descriptor, credentials))

        driver2 = LocalFileDriver(REGION, 'service')  # Create a separate, identical driver
        loaded_credentials = driver2.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_true(loaded_credentials.is_encrypted())
        assert_equal(loaded_credentials.get_data_kms_decrypted(), raw_credentials.encode())

    def test_save_errors_on_unencrypted(self):
        """LocalFileDriver - Save Errors on Unencrypted Credentials"""
        raw_credentials_dict = {
            'python': 'is very difficult',
            'someone': 'save meeeee',
        }
        descriptor = 'descriptor5'
        raw_credentials = json.dumps(raw_credentials_dict)

        credentials = Credentials(raw_credentials, False, REGION)

        assert_false(self._fs_driver.save_credentials(descriptor, credentials))
        assert_false(self._fs_driver.has_credentials(descriptor))

    def test_clear(self):
        """LocalFileDriver - Clear Credentials"""
        descriptor = 'descriptor'

        credentials = Credentials('aaaa', True, REGION)  # pretend it's encrypted
        self._fs_driver.save_credentials(descriptor, credentials)

        LocalFileDriver.clear()

        assert_false(self._fs_driver.has_credentials(descriptor))


#
# class TestSpooledTempfileDriver tests
#


class TestSpooledTempfileDriver:

    def setup(self):
        SpooledTempfileDriver.clear()
        self._sp_driver = SpooledTempfileDriver('service', REGION)

    @staticmethod
    def teardown():
        SpooledTempfileDriver.clear()

    def test_save_and_has_credentials(self):
        """SpooledTempfileDriver - Save and Has Credentials"""
        assert_false(self._sp_driver.has_credentials('descriptor'))

        credentials = Credentials('aaaa', True)  # let's pretend they're encrypted
        assert_true(self._sp_driver.save_credentials('descriptor', credentials))

        assert_true(self._sp_driver.has_credentials('descriptor'))

    @mock_kms
    def test_save_and_load_credentials(self):
        """SpooledTempfileDriver - Save and Load Credentials"""
        raw_credentials = 'aaaa'
        descriptor = 'descriptor'
        encrypted_raw_credentials = encrypt_with_kms(raw_credentials, REGION, KMS_ALIAS)

        credentials = Credentials(encrypted_raw_credentials, True, REGION)
        assert_true(self._sp_driver.save_credentials(descriptor, credentials))

        loaded_credentials = self._sp_driver.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_true(loaded_credentials.is_encrypted())
        assert_equal(loaded_credentials.get_data_kms_decrypted(), raw_credentials.encode())

    @mock_kms
    def test_save_and_load_credentials_persists_statically(self):
        """SpooledTempfileDriver - Save and Load Credentials"""
        raw_credentials_dict = {
            'python': 'is very difficult',
            'someone': 'save meeeee',
        }
        descriptor = 'descriptor'

        raw_credentials = json.dumps(raw_credentials_dict)
        encrypted_raw_credentials = encrypt_with_kms(raw_credentials, REGION, KMS_ALIAS)

        credentials = Credentials(encrypted_raw_credentials, True)
        assert_true(self._sp_driver.save_credentials(descriptor, credentials))

        driver2 = SpooledTempfileDriver('service', REGION)  # Create a separate, identical driver
        loaded_credentials = driver2.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_true(loaded_credentials.is_encrypted())
        assert_equal(loaded_credentials.get_data_kms_decrypted(), raw_credentials.encode())

    def test_save_errors_on_unencrypted(self):
        """SpooledTempfileDriver - Save Errors on Unencrypted Credentials"""
        raw_credentials = 'aaaa'
        descriptor = 'descriptor5'

        credentials = Credentials(raw_credentials, False)

        assert_false(self._sp_driver.save_credentials(descriptor, credentials))
        assert_false(self._sp_driver.has_credentials(descriptor))

    @patch('logging.Logger.error')
    def test_load_credentials_nonexistent(self, logging_error):
        """SpooledTempfileDriver - Load Credentials returns None on missing"""
        assert_false(self._sp_driver.has_credentials('qwertyuiop'))
        assert_is_none(self._sp_driver.load_credentials('qwertyuiop'))
        logging_error.assert_called_with(
            'SpooledTempfileDriver failed to load_credentials: Spool "%s" does not exist?',
            'service/qwertyuiop'
        )

    def test_clear(self):
        """SpooledTempfileDriver - Clear Credentials"""
        descriptor = 'descriptor'
        credentials = Credentials('aaaa', True)  # pretend it's encrypted

        assert_true(self._sp_driver.save_credentials(descriptor, credentials))

        SpooledTempfileDriver.clear()

        assert_false(self._sp_driver.has_credentials(descriptor))


#
# class EphemeralUnencryptedDriver tests
#

class TestEphemeralUnencryptedDriver:

    def setup(self):
        EphemeralUnencryptedDriver.clear()
        self._ep_driver = EphemeralUnencryptedDriver('service')

    @staticmethod
    def teardown():
        EphemeralUnencryptedDriver.clear()

    def test_save_and_has_credentials(self):
        """EphemeralUnencryptedDriver - Save and Has Credentials"""
        assert_false(self._ep_driver.has_credentials('descriptor'))

        credentials = Credentials('aaaa', False)
        assert_true(self._ep_driver.save_credentials('descriptor', credentials))

        assert_true(self._ep_driver.has_credentials('descriptor'))

    def test_save_and_load_credentials(self):
        """EphemeralUnencryptedDriver - Save and Load Credentials"""
        descriptor = 'descriptor'
        credentials = Credentials('aaaa', False)
        assert_true(self._ep_driver.save_credentials(descriptor, credentials))

        loaded_credentials = self._ep_driver.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_false(loaded_credentials.is_encrypted())
        assert_equal(loaded_credentials.data(), 'aaaa')

    def test_save_and_load_credentials_persists_statically(self):
        """EphemeralUnencryptedDriver - Save and Load Credentials"""
        descriptor = 'descriptor'
        credentials = Credentials('aaaa', False)

        assert_true(self._ep_driver.save_credentials(descriptor, credentials))

        driver2 = EphemeralUnencryptedDriver('service')  # Create a separate, identical driver
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

        raw_credentials = json.dumps(raw_credentials_dict)
        encrypted_raw_credentials = encrypt_with_kms(raw_credentials, REGION, KMS_ALIAS)

        credentials = Credentials(encrypted_raw_credentials, True, REGION)

        assert_true(self._ep_driver.save_credentials(descriptor, credentials))

        loaded_credentials = self._ep_driver.load_credentials(descriptor)

        assert_is_not_none(loaded_credentials)
        assert_false(loaded_credentials.is_encrypted())
        assert_equal(json.loads(loaded_credentials.data()), raw_credentials_dict)

    def test_clear(self):
        """EphemeralUnencryptedDriver - Clear Credentials"""
        descriptor = 'descriptor'

        credentials = Credentials('aaaa', False)
        self._ep_driver.save_credentials(descriptor, credentials)

        EphemeralUnencryptedDriver.clear()

        assert_false(self._ep_driver.has_credentials(descriptor))

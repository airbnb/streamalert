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

import json
import os
import shutil
import tempfile
from abc import abstractmethod

import boto3
from botocore.exceptions import ClientError

from stream_alert_cli.outputs.helpers import encrypt_and_push_creds_to_s3, kms_encrypt, \
    send_creds_to_s3

from stream_alert.shared.helpers.boto import REGION
from stream_alert.shared.logger import get_logger


LOGGER = get_logger(__name__)


class OutputCredentialsProvider(object):
    """OutputCredentialsProvider is a helper service to OutputDispatcher that helps it load
       credentials that are housed on AWS S3, or cached locally.

       OutputDispatcher implementations may require credentials to authenticate with an external
       gateway. All credentials for OutputDispatchers are to be stored in a single bucket on AWS S3
       and are encrypted with AWS KMS. When the OutputDispatchers are booted, this these encrypted
       credentials are downloaded and cached locally on the filesystem. Then, AWS KMS is used to
       decrypt the credentials when in use.

    Public methods:
        load_credentials: Returns a dict of the credentials requested
        get_local_credentials_temp_dir(): Returns full path to a temporary directory where all
            encrypted credentials are cached.

    """

    def __init__(self, config, defaults, service_name, prefix=None, aws_account_id=None):
        self._config = config
        self._region = REGION
        self._defaults = defaults
        self._service_name = service_name

        # Dependency on os package
        if prefix is None:
            prefix = os.environ['STREAMALERT_PREFIX']

        if aws_account_id is None:
            aws_account_id = os.environ['AWS_ACCOUNT_ID']

        self._prefix = prefix
        self._account_id = aws_account_id

        # Drivers are strategies utilized by this class for fetching credentials from various
        # locations on disk or remotely
        self._drivers = []  # type: list[CredentialsProvidingDriver]
        self._core_driver = None  # type: S3Driver
        self._setup_drivers()

    def _setup_drivers(self):
        """Initializes all drivers utilized by this OutputCredentialsProvider

        The Drivers are sequentially checked in the order they are appended to the driver list"""

        # Ephemeral driver
        ep_driver = EphemeralUnencryptedDriver(self._service_name)
        self._drivers.append(ep_driver)

        # # Always check local filesystem to see if credentials are cached in a Temp Directory
        # fs_driver = LocalFileDriver(self._region, self._service_name)
        # self._drivers.append(fs_driver)

        # Fall back onto downloading encrypted credentials from S3
        s3_driver = S3Driver(self._prefix, self._service_name, self._region, cache_driver=ep_driver)
        self._core_driver = s3_driver
        self._drivers.append(s3_driver)

    def save_credentials(self, descriptor, kms_key_alias, props):
        """
        Args:
            descriptor (str): OutputDispatcher descriptor
            kms_key_alias (str): KMS Key alias provided by configs
            props (Dict(str, OutputProperty)): A dict containing strings mapped to OutputProperty
                objects.

        Returns:
            bool: True is credentials successfully saved. False otherwise.
        """

        creds = {name: prop.value
                 for (name, prop) in props.iteritems() if prop.cred_requirement}

        credentials = Credentials(creds, False, self._region)
        return self._core_driver.save_credentials_into_s3(descriptor, credentials, kms_key_alias)

    def load_credentials(self, descriptor):
        """First try to load the credentials from /tmp and then resort to pulling
           the credentials from S3 if they are not cached locally

        Args:
            descriptor (str): unique identifier used to look up these credentials

        Returns:
            dict: the loaded credential info needed for sending alerts to this service
                or None if nothing gets loaded
        """
        credentials = None
        for driver in self._drivers:
            if driver.has_credentials(descriptor):
                credentials = driver.load_credentials(descriptor)
                break

        if not credentials:
            LOGGER.error('All drivers failed to retrieve credentials for [%s.%s]',
                         self._service_name,
                         descriptor)
            decrypted_creds = ''
        elif credentials.is_encrypted():
            decrypted_creds = credentials.get_data_kms_decrypted()
        else:
            decrypted_creds = credentials.data()

        creds_dict = json.loads(decrypted_creds)

        # Add any of the hard-coded default output props to this dict (ie: url)
        defaults = self._defaults
        if defaults:
            creds_dict.update(defaults)

        return creds_dict

    def kms_decrypt(self, data):
        """DEPRECATED - NO LONGER USED
        """
        try:
            client = boto3.client('kms', region_name=self._region)
            response = client.decrypt(CiphertextBlob=data)
            return response['Plaintext']
        except ClientError as err:
            LOGGER.error('an error occurred during credentials decryption: %s', err.response)

    @staticmethod
    def get_formatted_output_credentials_name(service_name, descriptor):
        """Formats the output name for this credential by combining the service
        and the descriptor.

        Args:
            service_name (str): Service name on output class (i.e. "pagerduty", "demisto")
            descriptor (str): Service destination (ie: slack channel, pd integration)

        Returns:
            str: Formatted credential name (ie: slack_ryandchannel)
        """
        cred_name = str(service_name)

        # should descriptor be enforced in all rules?
        if descriptor:
            cred_name = '{}/{}'.format(cred_name, descriptor)

        return cred_name

    def get_aws_account_id(self):
        """Returns the AWS account ID"""
        return self._account_id


class Credentials(object):
    """Encapsulation for a set of credentials, encrypted or not."""

    def __init__(self, data, is_encrypted=False, region=None):
        self._data = data
        self._is_encrypted = is_encrypted
        self._region = region if is_encrypted else None  # No use for region if unencrypted

    def is_encrypted(self):
        return self._is_encrypted

    def data(self):
        return self._data

    def get_data_kms_decrypted(self):
        if not self._is_encrypted:
            return None

        try:
            client = boto3.client('kms', region_name=self._region)
            response = client.decrypt(CiphertextBlob=self._data)
            return response['Plaintext']
        except ClientError as err:
            LOGGER.error('an error occurred during credentials decryption: %s', err.response)


class CredentialsProvidingDriver(object):
    """Drivers encapsulate logic for loading credentials"""

    @abstractmethod
    def load_credentials(self, descriptor):
        """
        Implementation that loads the given credentials into a new Credentials object. The
        behavior can be nondeterministic if has_credentials() is false.

        Args:
            descriptor (string): Descriptor for the current output service

        Return:
            Credentials|None: Returns None when loading fails.
        """

    @abstractmethod
    def has_credentials(self, descriptor):
        """
        Implementation that determines whether the current driver is capable of loading the
        requested credentials

        Args:
            descriptor (string): Descriptor for the current output service

        Return:
            bool: True if this driver has the requested Credentials, false otherwise.
        """


class FileDescriptorProvider(object):
    """Interface for Drivers capable of offering file-handles to aid in download of credentials."""

    @abstractmethod
    def offer_fileobj(self, descriptor):
        """
        Offers a file-like object. The caller is expected to call this method in a with block,
        and this file-like object is expected to automatically close.

        Returns:
             file object
        """


class CredentialsCachingDriver(object):
    """Interface for Drivers capable of being used as a caching layer to accelerate the speed
    of credential loading."""

    @abstractmethod
    def save_credentials(self, descriptor, credentials):
        """
        Saves the given credentials, such that on a subsequent call of load_credentials(), the
        same credentials will be loaded.

        Args:
            descriptor (str): OutputDispatcher descriptor
            credentials (Credentials): The credentials object to save. Notably, certain drivers are
                incapable of (or disallowed from) saving credentials that are unencrypted.

        Return:
            bool: True if saving succeeds. False otherwise.
        """
        pass


def get_formatted_output_credentials_name(service_name, descriptor):
    """Formats the output name for this credential by combining the service
    and the descriptor.

    Args:
        service_name (str): Service name on output class (i.e. "pagerduty", "demisto")
        descriptor (str): Service destination (ie: slack channel, pd integration)

    Returns:
        str: Formatted credential name (ie: slack_ryandchannel)
    """
    cred_name = str(service_name)

    # should descriptor be enforced in all rules?
    if descriptor:
        cred_name = '{}/{}'.format(cred_name, descriptor)

    return cred_name


class S3Driver(CredentialsProvidingDriver):
    """Driver for fetching credentials from AWS S3"""

    def __init__(self, prefix, service_name, region, file_driver=None, cache_driver=None):
        """
        Args:
            prefix (str): StreamAlert account prefix in configs
            service_name (str): The service name for the OutputDispatcher using this
            region (str): AWS Region
            file_driver (FileDescriptorProvider|None):
                Optional. When provided, the file_driver will be used to provide a File handle
                for downloading the S3 credentials into. This can be useful if it is desired to
                download the S3 credentials into a specific file for examination.

                If omitted, will defaulted to using SpooledTempfileDriver, which downloads
                the S3 file into memory temporarily, and is cleaned up afterward.

                In all cases, the credentials file is downloaded and stored in the file-like
                handle in ENCRYPTED FORM.

            cache_driver (CredentialsProvidingDriver|None):
                Optional. When provided, the downloaded credentials will be cached in the given
                driver. This is useful for reducing the number of S3/KMS calls and speeding up the
                system.

                (!) Storage encryption of the credentials is determined by the driver.
        """
        self._service_name = service_name
        self._region = region
        self._prefix = prefix
        self._bucket = self.get_s3_secrets_bucket()

        self._file_driver = file_driver  # type: FileDescriptorProvider
        if not self._file_driver:
            self._file_driver = SpooledTempfileDriver(self._service_name, self._region)

        self._cache_driver = cache_driver  # type: CredentialsCachingDriver

    def load_credentials(self, descriptor):
        """Pull the encrypted credential blob for this service and destination from s3
           and save it to a local file.

        Args:
            descriptor (str): Service destination (ie: slack channel, pd integration)

        Returns:
            Credentials: The loaded Credentials. None on failure
        """
        try:
            with self._file_driver.offer_fileobj(descriptor) as fd:
                client = boto3.client('s3', region_name=self._region)
                client.download_fileobj(
                    self._bucket,
                    self.get_s3_key(descriptor),
                    fd
                )

                fd.seek(0)
                enc_creds = fd.read()

            credentials = Credentials(enc_creds, True, self._region)
            if self._cache_driver:
                self._cache_driver.save_credentials(descriptor, credentials)

            return credentials
        except ClientError as err:
            LOGGER.exception('credentials for \'%s\' could not be downloaded '
                             'from S3: %s',
                             get_formatted_output_credentials_name(self._service_name, descriptor),
                             err.response)

    def has_credentials(self, descriptor):
        """Always returns True, as S3 is the place where all encrypted credentials are
           guaranteed to be cold-stored."""
        return True

    def save_credentials_into_s3(self, descriptor, credentials, kms_key_alias):
        """
        Takes the given credentials, encrypts them, and saves them into a determined S3 bucket
        and location.

        Notably, this implementation is NOT for the CredentialsCachingDriver interface, as the
        S3Driver is not a caching driver.

        Args:
            descriptor (str):
            credentials (Credentials):
            kms_key_alias (str):

        Returns:
            bool: True on success, False otherwise.
        """
        if credentials.is_encrypted():
            # Don't try saving encrypted credentials, or you will doubly-encrypt them, since this
            # method will encrypt the credentials immediately prior to saving into S3.
            raise RuntimeError('Cannot save encrypted credentials')

        s3_key = get_formatted_output_credentials_name(self._service_name, descriptor)

        # Encrypt the creds and push them to S3
        # then update the local output configuration with properties
        creds = credentials.data()
        if not creds:
            return True

        creds_json = json.dumps(creds)
        enc_creds = kms_encrypt(self._region, creds_json, kms_key_alias)
        return send_creds_to_s3(self._region, self._bucket, s3_key, enc_creds)

    def get_s3_key(self, descriptor):
        """
        Returns an appropriate S3 bucket key for credentials relevant to this Output

        Args:
            descriptor (str):

        Returns:
            string
        """
        return get_formatted_output_credentials_name(self._service_name, descriptor)

    def get_s3_secrets_bucket(self):
        """
        Returns an appropriate S3 bucket for all credentials relevant to this driver.

        Returns:
            string
        """
        return '{}.streamalert.secrets'.format(self._prefix)


class LocalFileDriver(CredentialsProvidingDriver, FileDescriptorProvider, CredentialsCachingDriver):
    """Driver for fetching credentials that are saved locally on the filesystem."""

    def __init__(self, region, service_name):
        self._region = region
        self._service_name = service_name
        self._temp_dir = self.get_local_credentials_temp_dir()

    def load_credentials(self, descriptor):
        local_cred_location = self.get_file_path(descriptor)
        with open(local_cred_location, 'rb') as cred_file:
            encrypted_credentials = cred_file.read()

        return Credentials(encrypted_credentials, True, self._region)

    def has_credentials(self, descriptor):
        return os.path.exists(self.get_file_path(descriptor))

    def save_credentials(self, descriptor, credentials):
        if not credentials.is_encrypted():
            LOGGER.error('Error: Writing unencrypted credentials to disk is disallowed.')
            return False

        with self.offer_fileobj(descriptor) as fp:
            fp.write(credentials.data())
        return True

    @staticmethod
    def clear():
        """Remove the local secrets directory that may be left from previous runs"""
        secrets_dirtemp_dir = LocalFileDriver.get_local_credentials_temp_dir()

        # Check if the folder exists, and remove it if it does
        if os.path.isdir(secrets_dirtemp_dir):
            shutil.rmtree(secrets_dirtemp_dir)

    def offer_fileobj(self, descriptor):
        """If you use the return value in a `with` statement block then the file descriptor
        will auto-close.

        Return:
            file object
        """
        file_path = self.get_file_path(descriptor)
        if not os.path.exists(file_path):
            os.makedirs(os.path.dirname(file_path))

        return open(file_path, 'a+b')  # read+write and in binary mode

    def get_file_path(self, descriptor):
        local_cred_location = os.path.join(
            self._temp_dir,
            get_formatted_output_credentials_name(self._service_name, descriptor)
        )
        return local_cred_location

    @staticmethod
    def get_formatted_output_credentials_name(service_name, descriptor):
        # FIXME (derek.wang) Is this still being used? Deprecated?
        return get_formatted_output_credentials_name(service_name, descriptor)

    @staticmethod
    def get_local_credentials_temp_dir():
        """Get the local tmp directory for caching the encrypted service credentials.
           Will automatically create a new directory

        Returns:
            str: local path for stream_alert_secrets tmp directory
        """
        temp_dir = os.path.join(tempfile.gettempdir(), "stream_alert_secrets")

        # Check if this item exists as a file, and remove it if it does
        if os.path.isfile(temp_dir):
            os.remove(temp_dir)

        # Create the folder on disk to store the credentials temporarily
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

        return temp_dir


class SpooledTempfileDriver(CredentialsProvidingDriver, FileDescriptorProvider):
    """Driver for fetching credentials that are stored in memory in file-like objects."""

    SERVICE_SPOOLS = {}

    def __init__(self, service_name, region):
        self._service_name = service_name
        self._region = region
        self._spools = {}

    def has_credentials(self, descriptor):
        key = self.get_spool_cache_key(descriptor)
        return key in SpooledTempfileDriver.SERVICE_SPOOLS

    def load_credentials(self, descriptor):
        key = self.get_spool_cache_key(descriptor)
        spool = SpooledTempfileDriver.SERVICE_SPOOLS[key]
        if not spool:
            LOGGER.error(
                'SpooledTempfileDriver failed to load_credentials: Spool "%s" does not exist?',
                self.get_spool_cache_key(descriptor)
            )
            return None

        spool.seek(0)
        raw_data = spool.read()

        return Credentials(raw_data, True, self._region)

    def save_credentials(self, descriptor, credentials):
        """
        Args:
            descriptor (str):
            credentials (Credentials):

        Return:
            bool
        """

        # Always store unencrypted because it's in memory. Saves calls to KMS and it's safe
        # because other unrelated processes cannot read this memory (probably..)
        if not credentials.is_encrypted():
            LOGGER.error('Error: Writing unencrypted credentials to disk is disallowed.')
            return False

        raw_creds = credentials.data()

        spool = tempfile.SpooledTemporaryFile()
        spool.write(raw_creds)

        key = self.get_spool_cache_key(descriptor)
        SpooledTempfileDriver.SERVICE_SPOOLS[key] = spool

        return True

    @staticmethod
    def clear():
        # De-allocating the spools triggers garbage collection, which implicitly closes the
        # file handles.
        SpooledTempfileDriver.SERVICE_SPOOLS = {}

    def offer_fileobj(self, descriptor):
        """If you use the return value in a `with` statement block then the file descriptor
           auto-close.

           NOTE: (!) This returns an ephemeral spool that is not attached to the caching mechanism
                 in save_credentials() and load_credentials()

        Returns:
            file object
        """
        return tempfile.SpooledTemporaryFile(0, 'a+b')

    def get_spool_cache_key(self, descriptor):
        return '{}/{}'.format(self._service_name, descriptor)


class EphemeralUnencryptedDriver(CredentialsProvidingDriver, CredentialsCachingDriver):
    """This driver stores credentials UNENCRYPTED on the Python runtime stack. It is ephemeral
    and is only readable by the current Python process... hopefully."""

    CREDENTIALS_STORE = {}

    def __init__(self, service_name):
        self._service_name = service_name

    def has_credentials(self, descriptor):
        key = self.get_storage_key(descriptor)
        return key in EphemeralUnencryptedDriver.CREDENTIALS_STORE

    def load_credentials(self, descriptor):
        key = self.get_storage_key(descriptor)
        unencrypted_raw_creds = EphemeralUnencryptedDriver.CREDENTIALS_STORE[key]

        return Credentials(unencrypted_raw_creds, False)

    def save_credentials(self, descriptor, credentials):
        """
        Args:
            descriptor (str):
            credentials (Credentials):

        Return:
            bool
        """
        if credentials.is_encrypted():
            unencrypted_raw_creds = credentials.get_data_kms_decrypted()
        else:
            unencrypted_raw_creds = credentials.data()

        key = self.get_storage_key(descriptor)
        EphemeralUnencryptedDriver.CREDENTIALS_STORE[key] = unencrypted_raw_creds
        return True

    @staticmethod
    def clear():
        EphemeralUnencryptedDriver.CREDENTIALS_STORE = {}

    def get_storage_key(self, descriptor):
        return '{}/{}'.format(self._service_name, descriptor)

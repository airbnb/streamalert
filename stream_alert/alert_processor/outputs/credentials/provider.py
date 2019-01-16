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

        # Always check local filesystem to see if credentials are cached in a Temp Directory
        fs_driver = LocalFileDriver(self._region, self._service_name)
        self._drivers.append(fs_driver)

        # Fall back onto downloading encrypted credentials from S3
        s3_driver = S3Driver(self._prefix, self._service_name, self._region, fs_driver)
        self._core_driver = s3_driver
        self._drivers.append(s3_driver)

    def save_credentials(self, descriptor, kms_key_alias, props):
        """
        Args:
            descriptor (str):
            kms_key_alias (str):
            props (Dict(str, OutputProperty)):

        Returns:
            bool
        """

        creds = {name: prop.value
                 for (name, prop) in props.iteritems() if prop.cred_requirement}

        credentials = Credentials(creds, False, self._region)
        return self._core_driver.save_credentials(descriptor, credentials, kms_key_alias)

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

    @staticmethod
    def get_local_credentials_temp_dir():
        """DEPREACTED - NO LONGER USED
        """
        temp_dir = os.path.join(tempfile.gettempdir(), "stream_alert_secrets")

        # Check if this item exists as a file, and remove it if it does
        if os.path.isfile(temp_dir):
            os.remove(temp_dir)

        # Create the folder on disk to store the credentials temporarily
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

        return temp_dir

    def load_encrypted_credentials_from_s3(self, cred_location, descriptor):
        """DEPRECATED - NO LONGER USED
        """
        try:
            fsd = LocalFileDriver(self._service_name, self._service_name)
            s3d = S3Driver(self._prefix, self._service_name, self._region, fsd)

            c = s3d.load_credentials(descriptor)
            return True
        except ClientError as err:
            LOGGER.exception('credentials for \'%s\' could not be downloaded '
                             'from S3: %s',
                             self.get_formatted_output_credentials_name(self._service_name,
                                                                        descriptor),
                             err.response)

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
        Args:
            descriptor (string): Descriptor for the current output service

        Return:
            Credentials
        """
        pass

    @abstractmethod
    def has_credentials(self, descriptor):
        """
        Args:
            descriptor (string): Descriptor for the current output service

        Return:
            bool: True if this driver has the requested Credentials, false otherwise.
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
    """Driver for fetching credentials from AWS S3

    Optionally, the S3 can be supplied with a LocalFileDriver to cache the encrypted credentials
    payload to the local filesystem.
    """

    def __init__(self, prefix, service_name, region, file_driver=None):
        self._service_name = service_name
        self._region = region
        self._prefix = prefix
        self._bucket = self.get_s3_secrets_bucket()

        self._file_driver = file_driver

    def load_credentials(self, descriptor):
        """Pull the encrypted credential blob for this service and destination from s3
           and save it to a local file.

        Args:
            descriptor (str): Service destination (ie: slack channel, pd integration)

        Returns:
            Credentials: The loaded Credentials. None on failure
        """
        try:
            if self._file_driver:
                fd = None
                local_cred_location = self._file_driver.get_file_path(descriptor)
            else:
                fd, local_cred_location = tempfile.mkstemp(
                    dir=LocalFileDriver.get_local_credentials_temp_dir()
                )  # Use some random temporary file

            if not os.path.exists(local_cred_location):
                os.makedirs(os.path.dirname(local_cred_location))

            client = boto3.client('s3', region_name=self._region)
            with open(local_cred_location, 'wb') as cred_output:
                client.download_fileobj(
                    self._bucket,
                    self.get_s3_key(descriptor),
                    cred_output
                )

            with open(local_cred_location, 'rb') as cred_file:
                enc_creds = cred_file.read()

            # Make sure to close the fd opened during mkstemp()
            if fd:
                os.close(fd)

            return Credentials(enc_creds, True, self._region)
        except ClientError as err:
            LOGGER.exception('credentials for \'%s\' could not be downloaded '
                             'from S3: %s',
                             get_formatted_output_credentials_name(self._service_name, descriptor),
                             err.response)

    def has_credentials(self, descriptor):
        """Always returns True, as S3 is the place where all encrypted credentials are
           guaranteed to be cold-stored."""
        return True

    def save_credentials(self, descriptor, credentials, kms_key_alias):
        if credentials.is_encrypted():
            # FIXME (derek.wang)
            raise RuntimeError('Dont try save encrypted creds to S3 or you will doubly encrypt')

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
        return get_formatted_output_credentials_name(self._service_name, descriptor)

    def get_s3_secrets_bucket(self):
        return '{}.streamalert.secrets'.format(self._prefix)


class LocalFileDriver(CredentialsProvidingDriver):
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


class SpooledTempfileDriver(CredentialsProvidingDriver):
    def has_credentials(self, descriptor):
        pass

    def load_credentials(self, descriptor):
        pass


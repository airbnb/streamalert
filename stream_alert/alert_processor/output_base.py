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
from abc import ABCMeta, abstractmethod
from collections import namedtuple
import json
import os
import ssl
import tempfile
import urllib2

import boto3
from botocore.exceptions import ClientError

from stream_alert.alert_processor import LOGGER

OutputProperty = namedtuple('OutputProperty',
                            'description, value, input_restrictions, mask_input, cred_requirement')
OutputProperty.__new__.__defaults__ = ('', '', {' ', ':'}, False, False)


class OutputRequestFailure(Exception):
    """OutputRequestFailure handles any HTTP failures"""


class StreamOutputBase(object):
    """StreamOutputBase is the base class to handle routing alerts to outputs

    Public methods:
        get_secrets_bucket_name: returns the name of the s3 bucket for secrets that
            includes a unique prefix
        output_cred_name: the name that is used to store the credentials both on s3
            and locally on disk in tmp
        get_config_service: the name of the service used by the config to store any
            configured outputs for this service. implemented by some subclasses, but
            subclass is not required to implement
        format_output_config: returns a formatted version of the outputs configuration
            that is to be written to disk
        get_user_defined_properties: returns any properties for this output that must be
            provided by the user. must be implemented by subclasses
        dispatch: handles the actual sending of alerts to the configured service. must
            be implemented by subclass
    """
    __metaclass__ = ABCMeta
    __service__ = NotImplemented

    def __init__(self, region, function_name, config):
        self.region = region
        self.secrets_bucket = self._get_secrets_bucket_name(function_name)
        self.config = config

    @staticmethod
    def _local_temp_dir():
        """Get the local tmp directory for caching the encrypted service credentials

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

    def _load_creds(self, descriptor):
        """First try to load the credentials from /tmp and then resort to pulling
        the credentials from S3 if they are not cached locally

        Args:
            descriptor (str): unique identifier used to look up these credentials

        Returns:
            dict: the loaded credential info needed for sending alerts to this service
                or None if nothing gets loaded
        """
        local_cred_location = os.path.join(self._local_temp_dir(),
                                           self.output_cred_name(descriptor))

        # Creds are not cached locally, so get the encrypted blob from s3
        if not os.path.exists(local_cred_location):
            if not self._get_creds_from_s3(local_cred_location, descriptor):
                return

        # Open encrypted credential file
        with open(local_cred_location, 'rb') as cred_file:
            enc_creds = cred_file.read()

        # Get the decrypted credential json from kms and load into dict
        # This could be None if the kms decryption fails, so check it
        decrypted_creds = self._kms_decrypt(enc_creds)
        if not decrypted_creds:
            return

        creds_dict = json.loads(decrypted_creds)

        # Add any of the hard-coded default output props to this dict (ie: url)
        defaults = self._get_default_properties()
        if defaults:
            creds_dict.update(defaults)

        return creds_dict

    @classmethod
    def _get_secrets_bucket_name(cls, function_name):
        """Returns the streamalerts secrets s3 bucket name"""
        prefix = function_name.split('_')[0]
        return '.'.join([prefix, 'streamalert', 'secrets'])

    def _get_creds_from_s3(self, cred_location, descriptor):
        """Pull the encrypted credential blob for this service and destination from s3

        Args:
            cred_location (str): The tmp path on disk to to store the encrypted blob
            descriptor (str): Service destination (ie: slack channel, pd integration)

        Returns:
            bool: True if download of creds from s3 was a success
        """
        try:
            if not os.path.exists(os.path.dirname(cred_location)):
                os.makedirs(os.path.dirname(cred_location))

            client = boto3.client('s3', region_name=self.region)
            with open(cred_location, 'wb') as cred_output:
                client.download_fileobj(self.secrets_bucket,
                                        self.output_cred_name(descriptor),
                                        cred_output)

            return True
        except ClientError as err:
            LOGGER.exception('credentials for \'%s\' could not be downloaded '
                             'from S3: %s', self.output_cred_name(descriptor),
                             err.response)

    def _kms_decrypt(self, data):
        """Decrypt data with AWS KMS.

        Args:
            data (str): An encrypted ciphertext data blob

        Returns:
            str: Decrypted json string
        """
        try:
            client = boto3.client('kms', region_name=self.region)
            response = client.decrypt(CiphertextBlob=data)
            return response['Plaintext']
        except ClientError as err:
            LOGGER.error('an error occurred during credentials decryption: %s', err.response)

    def _log_status(self, success):
        """Log the status of sending the alerts

        Args:
            success (bool): Indicates if the dispatching of alerts was successful
        """
        if success:
            LOGGER.info('Successfully sent alert to %s', self.__service__)
        else:
            LOGGER.error('Failed to send alert to %s', self.__service__)

        return bool(success)

    @staticmethod
    def _request_helper(url, data, headers=None, verify=True):
        """URL request helper to send a payload to an endpoint

        Args:
            url (str): Endpoint for this request
            data (str): Payload to send with this request
            headers (dict): Dictionary containing request-specific header parameters
            verify (bool): Whether or not SSL should be used for this request
        Returns:
            file handle: Contains the http response to be read
        """
        try:
            context = None
            if not verify:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            http_headers = headers or {}

            # Omitting data means a GET request should occur, not POST
            if not data:
                request = urllib2.Request(url, headers=http_headers)
            else:
                request = urllib2.Request(url, data=data, headers=http_headers)
            resp = urllib2.urlopen(request, context=context)
            return resp
        except urllib2.HTTPError as err:
            raise OutputRequestFailure('Failed to send to {} - [{}]'.format(err.url, err.code))

    @staticmethod
    def _check_http_response(resp):
        return resp and (200 <= resp.getcode() <= 299)

    @classmethod
    def _get_default_properties(cls):
        """Base method for retrieving properties that should be hard-coded for this
        output service integration. This could include information such as a static
        url used for sending the alerts to this service, a static port, or other
        non-sensitive information.

        If information of this sort is needed, this should be overridden in output subclasses.

        NOTE: This should not contain any sensitive or use-case specific data. Information
        such as this should be retrieved from the user using `get_user_defined_properties()`
        so the user is prompted for the sensitive information at configuration time and said
        information is then sent to kms for encryption and s3 for storage.

        Returns:
            dict: Contains various default items for this output (ie: url)
        """
        pass

    def output_cred_name(self, descriptor):
        """Formats the output name for this credential by combining the service
        and the descriptor.

        Args:
            descriptor (str): Service destination (ie: slack channel, pd integration)

        Returns:
            str: Formatted credential name (ie: slack_ryandchannel)
        """
        cred_name = str(self.__service__)

        # should descriptor be enforced in all rules?
        if descriptor:
            cred_name = '{}/{}'.format(cred_name, descriptor)

        return cred_name

    def format_output_config(self, service_config, values):
        """Add this descriptor to the list of descriptor this service
           If the service doesn't exist, a new entry is added to an empty list

        Args:
            service_config (dict): Loaded configuration as a dictionary
            values (OrderedDict): Contains various OutputProperty items
        Returns:
            [list<string>] List of descriptors for this service
        """
        return service_config.get(self.__service__, []) + [values['descriptor'].value]

    @abstractmethod
    def get_user_defined_properties(self):
        """Base method for retrieving properties that must be asssigned by the user when
        configuring a new output for this service. This should include any information that
        is sensitive or use-case specific. For intance, if the url needed for this integration
        is unique to your situation, it should be supplied here.

        If information of this sort is needed, it should be added to the method that
        overrides this one in the subclass.

        At the very minimum, subclass functions should return an OrderedDict that contains
        the key 'descriptor' with a description of the integration being configured

        Returns:
            OrderedDict: Contains various OutputProperty items
        """

    @abstractmethod
    def dispatch(self, **kwargs):
        """Send alerts to the given service. This base class just
            logs an error if not implemented on the inheriting class

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """

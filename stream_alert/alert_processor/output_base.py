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
import os
import ssl
import tempfile
import urllib2

from collections import namedtuple

import boto3
from botocore.exceptions import ClientError

from stream_alert.alert_processor.config import load_outputs_config, write_outputs_config

logging.basicConfig()
LOGGER = logging.getLogger('StreamOutput')

OutputProperty = namedtuple('OutputProperty',
                            'description, value, is_secret, cred_requirement')
OutputProperty.__new__.__defaults__ = ('', '', False, False)


class OutputRequestFailure(Exception):
    """OutputRequestFailure handles any HTTP failures"""


class OutputBase(object):
    """StreamOutputBase is the base class to handle routing alters to outputs

    """
    __service__ = NotImplemented
    __config_service__ = __service__

    def __init__(self, region, s3_prefix):
        self.region = region
        self.s3_prefix = self._format_prefix(s3_prefix)

    @staticmethod
    def _local_temp_dir():
        """Get the local tmp directory for caching the encrypted service credentials

        Returns:
            [string] local path for stream_alert_secrets tmp directory
        """
        temp_dir = os.path.join(tempfile.gettempdir(), "stream_alert_secrets")

        # Check if this item exists as a file, and remove it if it does
        if os.path.exists(temp_dir) and not os.path.isdir(temp_dir):
            os.remove(temp_dir)

        # Create the folder on disk to store the credentials temporarily
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

        return temp_dir

    def _load_creds(self, descriptor):
        """First try to load the credentials from /tmp and then resort to pulling
        the credentials from S3 if they are not cached locally

        Args:
            descriptor [string]: unique identifier used to look up these credentials

        Returns:
            [dict] the loaded credential info needed for sending alerts to this service
        """
        local_cred_location = os.path.join(self._local_temp_dir(),
                                           self._output_cred_name(descriptor))

        # Creds are not cached locally, so get the encrypted blob from s3
        if not os.path.exists(local_cred_location):
            if not self._get_creds_from_s3(local_cred_location, descriptor):
                return

        with open(local_cred_location, 'wb') as cred_file:
            enc_creds = cred_file.read()

        # Get the decrypted credential json from kms and load into dict
        # This could be None if the kms decryption fails, so check it
        decrypted_creds = self._kms_decrypt(enc_creds)
        if not decrypted_creds:
            return

        creds_dict = json.loads(decrypted_creds)

        # Add any of the hard-coded default output props to this dict (ie: url)
        defaults = self.get_default_properties()
        if defaults:
            creds_dict.update(defaults)

        return creds_dict

    def _format_s3_bucket(self, suffix):
        """Format the s3 bucket by combining the stored qualifier with a suffix

        Args:
            suffix [string]: suffix for an s3 bucket

        Returns:
            [string] the combined prefix and suffix
        """
        return '.'.join([self.s3_prefix, suffix])

    def _output_cred_name(self, descriptor):
        """Formats the output name for this credential by combining the service
        and the descriptor.

        Args:
            descriptor [string]: service destination (ie: slack channel, pd integration)

        Return:
            [string] the formatted credential name (ie: slack_ryandchannel)
        """
        cred_name = str(self.__service__)

        # should descriptor be enforced in all rules?
        if descriptor:
            cred_name = '{}_{}'.format(cred_name, descriptor)

        return cred_name

    def _get_creds_from_s3(self, cred_location, descriptor):
        """Pull the encrypted credential blob for this service and destination from s3

        Args:
            cred_location [string]: tmp path on disk to to store the encrypted blob
            descriptor [string]: service destination (ie: slack channel, pd integration)
        """
        try:
            client = boto3.client('s3', region_name=self.region)
            with open(cred_location, 'wb') as cred_output:
                client.download_fileobj(self._format_s3_bucket('streamalert.secrets'),
                                        self._output_cred_name(descriptor),
                                        cred_output)

            return True
        except ClientError as err:
            LOGGER.error('credentials for %s could not be downloaded from S3: %s',
                         self._output_cred_name(descriptor),
                         err.response)

    def _send_creds_to_s3(self, descriptor, blob_data):
        """Put the encrypted credential blob for this service and destination in s3

        Args:
            descriptor [string]: service destination (ie: slack channel, pd integration)
            blob_data [bytes]: cipher text blob from the kms encryption
        """
        try:
            client = boto3.client('s3', region_name=self.region)
            client.put_object(
                Body=blob_data,
                Bucket=self._format_s3_bucket('streamalert.secrets'),
                Key=self._output_cred_name(descriptor)
            )
        except ClientError as err:
            LOGGER.error('an error occurred while sending credentials for %s to S3: %s',
                         self._output_cred_name(descriptor),
                         err.response)
            raise err

    def _kms_encrypt(self, data):
        """Encrypt data with AWS KMS.

        Args:
            data [string]: json string to be encrypted

        Returns:
            [string] encrypted ciphertext data blob
        """
        try:
            client = boto3.client('kms', region_name=self.region)
            response = client.encrypt(KeyId='alias/stream_alert_secrets',
                                      Plaintext=data)
            return response['CiphertextBlob']
        except ClientError as err:
            LOGGER.error('an error occurred during credential encryption: %s', err.response)
            raise err

    def _kms_decrypt(self, data):
        """Decrypt data with AWS KMS.

        Args:
            data [string]: an encrypted ciphertext data blob

        Returns:
            [string] decrypted json string
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
            success [boolean]: indicates if the dispatching of alerts was successful
        """
        if success:
            LOGGER.info('successfully sent alert to %s', self.__service__)
        else:
            LOGGER.error('failed to send alert to %s', self.__service__)

    @staticmethod
    def _format_prefix(s3_prefix):
        """Return a bucket prefix that has been properly formatted

        Args:
            s3_prefix [string]: qualifier value to format

        Returns:
            [string] representing the formatted value
        """
        s3_prefix = s3_prefix.replace('_streamalert_alert_processor', '')
        return s3_prefix.replace('_', '.')

    @staticmethod
    def _request_helper(url, data, headers=None, verify=True):
        """URL request helper to send a payload to an endpoint

        Args:
            url [string]: endpoint for this request
            data [string]: payload to send with this request
            headers [dict=None]: dictionary containing request-specific header parameters
            verify [boolean=True]: whether or not SSL should be used for this request
        Returns:
            [file handle] contains the http response to be read
        """
        try:
            context = None
            if not verify:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            request = urllib2.Request(url, data=data, headers=headers)
            resp = urllib2.urlopen(request, context=context)
            return resp
        except urllib2.HTTPError as err:
            raise OutputRequestFailure('Failed to send to {} - [{}] {}'.format(err.url,
                                                                               err.code,
                                                                               err.read()))
    @staticmethod
    def _check_http_response(resp):
        return resp and (200 <= resp.getcode() <= 299)

    @classmethod
    def get_user_defined_properties(cls):
        """Base method for retrieving properties that must be asssigned by the user
        for a this output service integration. Overridden in output subclasses

        Returns:
            [OrderedDict] Contains various OutputProperty items
        """
        pass

    @classmethod
    def get_default_properties(cls):
        """Base method for retrieving properties that are hard coded for this
        output service integration. Overridden in output subclasses

        Returns:
            [OrderedDict] Contains various OutputProperty items
        """
        pass

    @classmethod
    def _check_output_exists(cls, service, config, props):
        """Determine if this service and destination combo has already been created

        Args:
            service [string]: the service for which the user is adding a configuration
            config [dict]: the outputs config that has been read from disk
            props [OrderedDict]: Contains various OutputProperty items

        Returns:
            [boolean] true if the service/destination exists already
        """
        if service in config and props['descriptor'].value in config[service]:
            LOGGER.error('this descriptor is already configured for %s. '
                         'please select a new and unique descriptor', service)
            return

        return True

    def _get_config_service(self):
        """Get the string used for saving this service to the config. AWS services
        are not named the same in the config as they are in the rules processor, so
        having the ability to return a string like 'aws-s3' instead of 's3' is required

        Returns:
            [string] service string used for looking up info in output configuration
        """
        return (self.__config_service__,
                self.__service__)[self.__config_service__ == NotImplemented]

    def format_output_config(self, config, props):
        """Add this descriptor to the list of descriptor this service
           If the service doesn't exist, a new entry is added to an empty list

        Args:
            config [dict]: the loaded configuration as a dictionary
            props [OrderedDict]: Contains various OutputProperty items
        Returns:
            [string] list of descriptors for this service
        """
        return config.get(self._get_config_service(), []) + [props['descriptor'].value]

    def load_config(self, props):
        """Gets the outputs config from disk and checks if the output already exists

        Args:
            props [OrderedDict]: Contains various OutputProperty items

        Returns:
            [dict] if the output doesn't exist, return the configuration, otherwise return false
        """
        config = load_outputs_config()
        service = self._get_config_service()
        if not self._check_output_exists(service, config, props):
            return False

        return config

    def update_outputs_config(self, config, props):
        """Updates and writes the outputs config back to disk

        Args:
            config [dict]: the loaded configuration as a dictionary
            props [OrderedDict]: Contains various OutputProperty items

        Returns:
            [dict] if the output doesn't exist, return the configuration, otherwise return false
        """
        service = self._get_config_service()
        config[service] = self.format_output_config(config, props)
        write_outputs_config(config)

    def dispatch(self, descriptor, rule_name, alert):
        """Send alerts to the given service. This base class just
            logs an error if not implemented on the inheriting class

        Args:
            descriptor [string]: Service descriptor (ie: slack channel, pd integration)
            rule_name [string]: The name of the triggered rule
            alert [dict]: The alert relevant to the triggered rule
        """
        LOGGER.error('unable to send alert for service %s', self.__service__)

    def push_creds_to_s3(self, user_input):
        """Construct a dictionary of the credentials we want to encrypt and send to s3

        """
        creds = {name: prop.value
                 for (name, prop) in user_input.iteritems() if prop.cred_requirement}

        # Check if we have any creds to send to s3
        # Some services (ie: AWS) do not require this, so it's not an error
        if not creds:
            return

        creds_json = json.dumps(creds)
        enc_creds = self._kms_encrypt(creds_json)
        self._send_creds_to_s3(user_input['descriptor'], enc_creds)

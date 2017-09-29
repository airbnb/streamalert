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

import boto3
from botocore.exceptions import ClientError

from stream_alert_cli.logger import LOGGER_CLI

OUTPUTS_CONFIG = 'outputs.json'


def load_outputs_config(conf_dir='conf'):
    """Load the outputs configuration file from disk

    Args:
        conf_dir (str): Directory to read outputs config from

    Returns:
        dict: The output configuration settings
    """
    with open(os.path.join(conf_dir, OUTPUTS_CONFIG)) as outputs:
        try:
            values = json.load(outputs)
        except ValueError:
            LOGGER_CLI.error(
                'The %s file could not be loaded into json',
                OUTPUTS_CONFIG)
            raise

    return values


def write_outputs_config(data, conf_dir='conf'):
    """Write the outputs configuration file back to disk

    Args:
        data (dict): Dictionary to be converted to json and written to disk
        conf_dir (str): Directory to write outputs config to
    """
    with open(os.path.join(conf_dir, OUTPUTS_CONFIG), 'w') as outputs:
        json.dump(data, outputs, indent=2, separators=(',', ': '), sort_keys=True)


def load_config(props, service):
    """Gets the outputs config from disk and checks if the output already exists

    Args:
        props (OrderedDict): Contains various OutputProperty items
        service (str): The service for which the user is adding a configuration

    Returns:
        dict: If the output doesn't exist, return the configuration, otherwise return False
    """
    config = load_outputs_config()
    if output_exists(config, props, service):
        return False

    return config


def encrypt_and_push_creds_to_s3(region, bucket, key, props, kms_key_alias):
    """Construct a dictionary of the credentials we want to encrypt and send to s3

    Args:
        region (str): The aws region to use for boto3 client
        bucket (str): The name of the s3 bucket to write the encrypted credentials to
        key (str): ID for the s3 object to write the encrypted credentials to
        props (OrderedDict): Contains various OutputProperty items
        kms_key_alias (string): The KMS key alias to use for encryption of S3 objects
    """
    creds = {name: prop.value
             for (name, prop) in props.iteritems() if prop.cred_requirement}

    # Check if we have any creds to send to s3
    # Some services (ie: AWS) do not require this, so it's not an error
    if not creds:
        return True

    creds_json = json.dumps(creds)
    enc_creds = kms_encrypt(region, creds_json, kms_key_alias)
    return send_creds_to_s3(region, bucket, key, enc_creds)


def kms_encrypt(region, data, kms_key_alias):
    """Encrypt data with AWS KMS.

    Args:
        region (str): AWS region to use for boto3 client
        data (str): json string to be encrypted
        kms_key_alias (str): The KMS key alias to use for encryption of S3 objects

    Returns:
        str: Encrypted ciphertext data blob
    """
    try:
        client = boto3.client('kms', region_name=region)
        response = client.encrypt(KeyId='alias/{}'.format(kms_key_alias),
                                  Plaintext=data)
        return response['CiphertextBlob']
    except ClientError:
        LOGGER_CLI.error('An error occurred during credential encryption')
        raise

def send_creds_to_s3(region, bucket, key, blob_data):
    """Put the encrypted credential blob for this service and destination in s3

    Args:
        region (str): AWS region to use for boto3 client
        bucket (str): The name of the s3 bucket to write the encrypted credentials to
        key (str): ID for the s3 object to write the encrypted credentials to
        blob_data (bytes): Cipher text blob from the kms encryption
    """
    try:
        client = boto3.client('s3', region_name=region)
        client.put_object(
            Body=blob_data,
            Bucket=bucket,
            Key=key,
            ServerSideEncryption='AES256'
        )

        return True
    except ClientError as err:
        LOGGER_CLI.error(
            'An error occurred while sending credentials to S3 for key \'%s\' '
            'in bucket \'%s\': %s',
            key,
            bucket,
            err.response['Error']['Message'])
        return False


def output_exists(config, props, service):
    """Determine if this service and destination combo has already been created

    Args:
        config (dict): The outputs config that has been read from disk
        props (OrderedDict): Contains various OutputProperty items
        service (str): The service for which the user is adding a configuration

    Returns:
        [boolean] True if the service/destination exists already
    """
    if service in config and props['descriptor'].value in config[service]:
        LOGGER_CLI.error('This descriptor is already configured for %s. '
                         'Please select a new and unique descriptor', service)
        return True

    return False


def update_outputs_config(config, updated_config, service):
    """Updates and writes the outputs config back to disk

    Args:
        config (dict): The loaded configuration as a dictionary
        updated_config: The updated configuration for this service. this could
            be a list, dictionary, etc depending on how this services stores config info
        service (str): The service whose configuration is being updated
    """
    config[service] = updated_config
    write_outputs_config(config)

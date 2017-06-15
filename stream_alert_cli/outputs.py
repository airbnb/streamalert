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

import boto3

from botocore.exceptions import ClientError

from stream_alert_cli.logger import LOGGER_CLI

OUTPUTS_CONFIG = 'outputs.json'

def load_outputs_config(conf_dir='conf'):
    """Load the outputs configuration file from disk

    Args:
        conf_dir [string='conf']: Directory to read outputs config from

    Returns:
        [dict] The output configuration settings
    """
    with open(os.path.join(conf_dir, OUTPUTS_CONFIG)) as outputs:
        try:
            values = json.load(outputs)
        except ValueError:
            LOGGER_CLI.exception('the %s file could not be loaded into json', OUTPUTS_CONFIG)

    return values

def write_outputs_config(data, conf_dir='conf'):
    """Write the outputs configuration file back to disk

    Args:
        data [dict]: Dictionary to be converted to json and written to disk
        conf_dir [string='conf']: Directory to write outputs config to
    """
    with open(os.path.join(conf_dir, OUTPUTS_CONFIG), 'w') as outputs:
        outputs.write(json.dumps(
            data,
            indent=2,
            separators=(',', ': '),
            sort_keys=True
        ))

def load_config(props, service):
    """Gets the outputs config from disk and checks if the output already exists

    Args:
        props [OrderedDict]: Contains various OutputProperty items
        service [string]: The service for which the user is adding a configuration

    Returns:
        [dict] If the output doesn't exist, return the configuration, otherwise return False
    """
    config = load_outputs_config()
    if not check_output_exists(config, props, service):
        return False

    return config

def encrypt_and_push_creds_to_s3(region, bucket, key, props):
    """Construct a dictionary of the credentials we want to encrypt and send to s3

    Args:
        region [string]: The aws region to use for boto3 client
        bucket [string]: The name of the s3 bucket to write the encrypted credentials to
        key [string]: ID for the s3 object to write the encrypted credentials to
        props [OrderedDict]: Contains various OutputProperty items
    """
    creds = {name: prop.value
             for (name, prop) in props.iteritems() if prop.cred_requirement}

    # Check if we have any creds to send to s3
    # Some services (ie: AWS) do not require this, so it's not an error
    if not creds:
        return

    creds_json = json.dumps(creds)
    enc_creds = kms_encrypt(region, creds_json)
    return send_creds_to_s3(region, bucket, key, enc_creds)

def kms_encrypt(region, data):
    """Encrypt data with AWS KMS.

    Args:
        region [string]: AWS region to use for boto3 client
        data [string]: json string to be encrypted

    Returns:
        [string] Encrypted ciphertext data blob
    """
    try:
        client = boto3.client('kms', region_name=region)
        response = client.encrypt(KeyId='alias/stream_alert_secrets',
                                  Plaintext=data)
        return response['CiphertextBlob']
    except ClientError:
        LOGGER_CLI.exception('an error occurred during credential encryption')

def send_creds_to_s3(region, bucket, key, blob_data):
    """Put the encrypted credential blob for this service and destination in s3

    Args:
        region [string]: AWS region to use for boto3 client
        bucket [string]: The name of the s3 bucket to write the encrypted credentials to
        key [string]: ID for the s3 object to write the encrypted credentials to
        blob_data [bytes]: Cipher text blob from the kms encryption
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
        LOGGER_CLI.error('An error occurred while sending credentials to S3 for key [%s]: '
                         '%s [%s]',
                         key,
                         err.response['Error']['Message'],
                         err.response['Error']['BucketName'])
        return False

def check_output_exists(config, props, service):
    """Determine if this service and destination combo has already been created

    Args:
        config [dict]: The outputs config that has been read from disk
        props [OrderedDict]: Contains various OutputProperty items
        service [string]: The service for which the user is adding a configuration

    Returns:
        [boolean] True if the service/destination exists already
    """
    if service in config and props['descriptor'].value in config[service]:
        LOGGER_CLI.error('this descriptor is already configured for %s. '
                         'please select a new and unique descriptor', service)
        return False

    return True

def update_outputs_config(config, updated_config, service):
    """Updates and writes the outputs config back to disk

    Args:
        config [dict]: The loaded configuration as a dictionary
        updated_config [variant]: The updated configuration for this service. this could
            be a list, dictionary, etc depending on how this services stores config info
        service [string]: The service whose configuration is being updated
    """
    config[service] = updated_config
    write_outputs_config(config)

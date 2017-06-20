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
from mock import mock_open, patch

import boto3
from botocore.exceptions import ClientError

from moto import mock_kms, mock_s3

from nose.tools import assert_false, assert_is_none, assert_list_equal, assert_true

from stream_alert.alert_processor.output_base import OutputProperty
from stream_alert_cli.outputs import (
    encrypt_and_push_creds_to_s3,
    load_config,
    load_outputs_config,
    update_outputs_config,
    write_outputs_config
)


def test_load_output_config():
    """Load outputs configuration"""
    config = load_outputs_config()
    loaded_config_keys = sorted(config.keys())

    expected_config_keys = [u'aws-lambda', u'aws-s3', u'pagerduty', u'phantom', u'slack']

    assert_list_equal(loaded_config_keys, expected_config_keys)


@patch('logging.Logger.exception')
def test_load_output_config_error(log_mock):
    """Load outputs configuration - exception"""
    mock = mock_open(read_data='non-json string that will raise an exception')
    with patch('__builtin__.open', mock):
        load_outputs_config()

    log_mock.assert_called_with(
        'the %s file could not be loaded into json',
        'outputs.json')


def test_write_outputs_config():
    """Write outputs configuration"""
    mock = mock_open()
    with patch('__builtin__.open', mock):
        # load_outputs_config()
        data = {'test': 'values', 'to': 'write'}
        write_outputs_config(data)

        mock.return_value.write.assert_called_with(
            """{
  "test": "values",
  "to": "write"
}"""
        )


def test_load_config():
    """Load config - check for existing output"""
    props = {
        'descriptor': OutputProperty(
            'short description',
            'sample_lambda')}
    loaded = load_config(props, 'aws-lambda')

    assert_false(loaded)


"""OutputProperty = namedtuple('OutputProperty',
                            'description, value, input_restrictions, mask_input, cred_requirement')
OutputProperty.__new__.__defaults__ = ('', '', {' ', ':'}, False, False)"""


@mock_kms
@mock_s3
def test_encrypt_and_push_creds_to_s3():
    """Encrypt and push creds to s3"""
    props = {
        'non-secret': OutputProperty(
            description='short description of info needed',
            value='http://this.url.value')}

    return_value = encrypt_and_push_creds_to_s3('us-east-1', 'bucket', 'key', props)

    assert_is_none(return_value)

    props['secret'] = OutputProperty(
        description='short description of secret needed',
        value='1908AGSG98A8908AG',
        cred_requirement=True)

    # Create the bucket to hold the mock object being put
    boto3.client('s3', region_name='us-east-1').create_bucket(Bucket='bucket')

    return_value = encrypt_and_push_creds_to_s3('us-east-1', 'bucket', 'key', props)

    assert_true(return_value)


@patch('boto3.client')
@patch('logging.Logger.exception')
def test_encrypt_and_push_creds_to_s3_kms_failure(log_mock, boto_mock):
    """Encrypt and push creds to s3 - kms failure"""
    props = {
        'secret': OutputProperty(
            description='short description of secret needed',
            value='1908AGSG98A8908AG',
            cred_requirement=True)}

    err_response = {
        'Error':
            {
                'Code': 100,
                'Message': 'BAAAD',
                'BucketName': 'bucket'
            }
    }

    # Add ClientError side_effect to mock
    boto_mock.side_effect = ClientError(err_response, 'operation')
    encrypt_and_push_creds_to_s3('us-east-1', 'bucket', 'key', props)

    log_mock.assert_called_with('an error occurred during credential encryption')


def test_update_outputs_config():
    """Update outputs config"""
    mock = mock_open()
    with patch('__builtin__.open', mock):
        service = 'mock_service'
        config = {service: ['value01', 'value02']}
        updated_config = ['value01', 'value02', 'value03']

        update_outputs_config(config, updated_config, service)

        mock.return_value.write.assert_called_with(
            """{
  "mock_service": [
    "value01",
    "value02",
    "value03"
  ]
}"""
        )

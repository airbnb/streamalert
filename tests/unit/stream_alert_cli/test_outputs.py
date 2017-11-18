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
import boto3
from botocore.exceptions import ClientError
from mock import mock_open, patch
from moto import mock_kms, mock_s3
from nose.tools import assert_false, assert_list_equal, assert_true, raises

from stream_alert.alert_processor.outputs.output_base import OutputProperty
from stream_alert_cli.outputs import (
    encrypt_and_push_creds_to_s3,
    load_config,
    load_outputs_config,
    update_outputs_config,
    write_outputs_config
)


def test_load_output_config():
    """CLI - Outputs - Load outputs configuration"""
    config = load_outputs_config('tests/unit/conf')
    loaded_config_keys = sorted(config.keys())

    expected_config_keys = [
        u'aws-firehose',
        u'aws-lambda',
        u'aws-s3',
        u'pagerduty',
        u'phantom',
        u'slack']

    assert_list_equal(loaded_config_keys, expected_config_keys)


@raises(ValueError)
def test_load_output_config_error():
    """CLI - Outputs - Load outputs configuration - exception"""
    mock = mock_open(read_data='non-json string that will raise an exception')
    with patch('__builtin__.open', mock):
        load_outputs_config()


@patch('json.dump')
def test_write_outputs_config(json_mock):
    """CLI - Outputs - Write outputs configuration"""
    with patch('__builtin__.open', new_callable=mock_open()) as mocker:
        data = {'test': 'values', 'to': 'write'}
        write_outputs_config(data)
        json_mock.assert_called_with(data, mocker.return_value.__enter__.return_value,
                                     indent=2, separators=(',', ': '), sort_keys=True)


@patch('stream_alert_cli.outputs.load_outputs_config')
def test_load_config(method_mock):
    """CLI - Outputs - Load config - check for existing output"""
    # Patch the return value of the load_outputs_config method to return
    # the unit testing outputs configuration
    method_mock.return_value = load_outputs_config(conf_dir="tests/unit/conf")
    props = {
        'descriptor': OutputProperty(
            'short description',
            'unit_test_lambda')}
    loaded = load_config(props, 'aws-lambda')

    assert_false(loaded)


@patch('stream_alert_cli.outputs.encrypt_and_push_creds_to_s3')
@mock_kms
@mock_s3
def test_encrypt_and_push_creds_to_s3(cli_mock):
    """CLI - Outputs - Encrypt and push creds to s3"""
    props = {
        'non-secret': OutputProperty(
            description='short description of info needed',
            value='http://this.url.value')}

    return_value = encrypt_and_push_creds_to_s3('us-east-1', 'bucket', 'key', props, 'test_alias')

    assert_true(return_value)
    cli_mock.assert_not_called()

    props['secret'] = OutputProperty(
        description='short description of secret needed',
        value='1908AGSG98A8908AG',
        cred_requirement=True)

    # Create the bucket to hold the mock object being put
    boto3.client('s3', region_name='us-east-1').create_bucket(Bucket='bucket')

    return_value = encrypt_and_push_creds_to_s3('us-east-1', 'bucket', 'key', props, 'test_alias')

    assert_true(return_value)


@raises(ClientError)
@patch('boto3.client')
@patch('logging.Logger.error')
def test_encrypt_and_push_creds_to_s3_kms_failure(log_mock, boto_mock):
    """CLI - Outputs - Encrypt and push creds to s3 - kms failure"""
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
    encrypt_and_push_creds_to_s3('us-east-1', 'bucket', 'key', props, 'test_alias')

    log_mock.assert_called_with('An error occurred during credential encryption')


@patch('json.dump')
def test_update_outputs_config(json_mock):
    """CLI - Outputs - Update outputs config"""
    with patch('__builtin__.open', new_callable=mock_open()) as mocker:
        service = 'mock_service'
        original_config = {service: ['value01', 'value02']}
        new_config_values = ['value01', 'value02', 'value03']

        update_outputs_config(original_config, new_config_values, service)

        expected_value = {'mock_service': ['value01', 'value02', 'value03']}

        json_mock.assert_called_with(expected_value, mocker.return_value.__enter__.return_value,
                                     indent=2, separators=(',', ': '), sort_keys=True)

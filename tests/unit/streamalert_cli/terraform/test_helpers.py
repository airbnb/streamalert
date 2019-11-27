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
from mock import Mock, patch
from nose.tools import assert_false, assert_true
from moto import mock_dynamodb2
from streamalert_cli.terraform.helpers import (
    create_tf_state_lock_ddb_table,
    destroy_tf_state_lock_ddb_table
)

from streamalert_cli.config import CLIConfig

CONFIG = CLIConfig(config_path='tests/unit/conf')
LOCK_TABLE = '{}_streamalert_terraform_state_lock'.format(CONFIG['global']['account']['prefix'])
REGION = CONFIG['global']['account']['region']

@mock_dynamodb2()
@patch('time.sleep', Mock())
def test_terraform_state_lock_create():
    create_tf_state_lock_ddb_table(REGION, LOCK_TABLE)
    client = boto3.client('dynamodb', REGION)
    # Verify table creation logic
    assert_true(LOCK_TABLE in client.list_tables()['TableNames'])
    desc_resp = client.describe_table(TableName=LOCK_TABLE)
    # Verify table is configured according to terraform docs
    assert_true({'AttributeName': 'LockID', 'KeyType': 'HASH'} in desc_resp['Table']['KeySchema'])

    expected_attr = {'AttributeName': 'LockID', 'AttributeType': 'S'}
    assert_true(expected_attr in desc_resp['Table']['AttributeDefinitions'])

@mock_dynamodb2()
def test_terraform_state_lock_destroy():
    # Verify destroy logic
    destroy_tf_state_lock_ddb_table(REGION, LOCK_TABLE)
    client = boto3.client('dynamodb', REGION)
    assert_false(LOCK_TABLE in client.list_tables()['TableNames'])

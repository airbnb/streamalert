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

from streamalert.shared.helpers.boto import default_config
from streamalert.shared.logger import get_logger
from streamalert_cli.helpers import run_command

LOGGER = get_logger(__name__)


def terraform_check():
    """Verify that Terraform is configured correctly

    Returns:
        bool: Success or failure of the command ran"""
    prereqs_message = ('Terraform not found! Please install and add to '
                       'your $PATH:\n'
                       '\t$ export PATH=$PATH:/usr/local/terraform/bin')
    return run_command(['terraform', 'version'], error_message=prereqs_message, quiet=True)


def create_tf_state_lock_ddb_table(region, table):
    """Create the DynamoDB table for terraform remote state locking

    Args:
        region (str): The AWS region to create the table in
        table (str): The name of the DynamoDB table to create
    """
    ddb_client = boto3.client('dynamodb', config=default_config(region=region))
    ddb_tables = ddb_client.list_tables()
    if table in ddb_tables['TableNames']:
        return
    LOGGER.info('Creating terraform state locking DynamoDB table')
    ddb_client.create_table(
        AttributeDefinitions=[{
            'AttributeName': 'LockID',
            'AttributeType': 'S'
        }],
        TableName=table,
        KeySchema=[{
            'AttributeName': 'LockID',
            'KeyType': 'HASH'
        }],
        BillingMode='PAY_PER_REQUEST'
    )
    waiter = ddb_client.get_waiter('table_exists')
    waiter.wait(TableName=table)


def destroy_tf_state_lock_ddb_table(region, table):
    """Destroy the DynamoDB table for terraform remote state locking

    Args:
        region (str): The AWS region to destroy the table in
        table (str): The name of the DynamoDB table to destroy
    """
    ddb_client = boto3.client('dynamodb', config=default_config(region=region))
    ddb_tables = ddb_client.list_tables()
    if table not in ddb_tables['TableNames']:
        return
    LOGGER.info('Destroying terraform state locking DynamoDB table')
    ddb_client.delete_table(TableName=table)
    waiter = ddb_client.get_waiter('table_not_exists')
    waiter.wait(TableName=table)

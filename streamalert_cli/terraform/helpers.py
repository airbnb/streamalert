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
import time
from streamalert_cli.helpers import run_command
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)

def terraform_check():
    """Verify that Terraform is configured correctly

    Returns:
        bool: Success or failure of the command ran"""
    prereqs_message = ('Terraform not found! Please install and add to '
                       'your $PATH:\n'
                       '\t$ export PATH=$PATH:/usr/local/terraform/bin')
    return run_command(['terraform', 'version'], error_message=prereqs_message, quiet=True)

def terraform_state_lock(action, region, table):
    ddb_client = boto3.client('dynamodb', region_name=region)
    ddb_tables = ddb_client.list_tables()
    if action == 'create':
        if table not in ddb_tables['TableNames']:
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
            wait = True
            while wait:
                desc_resp = ddb_client.describe_table(TableName=table)
                if desc_resp['Table']['TableStatus'] == 'ACTIVE':
                    wait = False
                else:
                    time.sleep(1)
    elif action == 'destroy':
        if table in ddb_tables['TableNames']:
            LOGGER.info('Destroying terraform state locking DynamoDB table')
            ddb_client.delete_table(TableName=table)

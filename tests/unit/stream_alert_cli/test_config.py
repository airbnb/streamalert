"""
Copyright 2017-present, Airbnb Inc.

Licensed under the Apache License, Version 2.0 (the 'License');
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an 'AS IS' BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import json

from nose.tools import assert_equal

from tests.unit.helpers.base import mock_open
from stream_alert_cli_module.config import CLIConfig


def test_load_config():
    """CLI - Load config"""
    config_data = {
        'global': {
            'account': {
                'aws_account_id': 'AWS_ACCOUNT_ID_GOES_HERE',
                'kms_key_alias': 'stream_alert_secrets',
                'prefix': 'unit-testing',
                'region': 'us-west-2'
            },
            'terraform': {
                'tfstate_bucket': 'PREFIX_GOES_HERE.streamalert.terraform.state',
                'tfstate_s3_key': 'stream_alert_state/terraform.tfstate',
                'tfvars': 'terraform.tfvars'
            },
            'infrastructure': {
                'monitoring': {
                    'create_sns_topic': True
                }
            }
        },
        'lambda': {
            'alert_processor_config': {
                'handler': 'stream_alert.alert_processor.main.handler',
                'source_bucket': 'PREFIX_GOES_HERE.streamalert.source',
                'source_current_hash': '<auto_generated>',
                'source_object_key': '<auto_generated>',
                'third_party_libraries': []
            },
            'rule_processor_config': {
                'handler': 'stream_alert.rule_processor.main.handler',
                'source_bucket': 'PREFIX_GOES_HERE.streamalert.source',
                'source_current_hash': '<auto_generated>',
                'source_object_key': '<auto_generated>',
                'third_party_libraries': [
                    'jsonpath_rw',
                    'netaddr'
                ]
            }
        }
    }

    global_file = 'conf/global.json'
    global_contents = json.dumps(config_data['global'], indent=2)

    lambda_file = 'conf/lambda.json'
    lambda_contents = json.dumps(config_data['lambda'], indent=2)

    with mock_open(global_file, global_contents):
        with mock_open(lambda_file, lambda_contents):
            # mock os call

            # test valid and invalid clusters

            config = CLIConfig()
            assert_equal(config['global']['account']['prefix'], 'unit-testing')

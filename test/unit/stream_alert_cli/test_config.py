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

# command: nosetests -v -s test/unit/
# specific test: nosetests -v -s test/unit/file.py:TestStreamPayload.test_name

import json
import io

from nose.tools import assert_equal, assert_not_equal, nottest
from mock import patch

from stream_alert_cli.config import CLIConfig

CONFIG_FILE = 'variables.json'

class TestCLIConfig(object):
    def setup(self):
        """Setup before each method"""
        pass

    def teardown(self):
        """Teardown after each method"""
        pass

    def test_v1_config(self):
        v1_config = {
            "account_id": "12345678911",
            "clusters": {
                "prod": "us-east-1"
            },
            "firehose_s3_bucket_suffix": "streamalert.results",
            "kinesis_settings": {
                "prod": [
                    1,
                    24
                ]
            },
            "kms_key_alias": "stream_alert_secrets",
            "lambda_function_prod_versions": {
                "prod": "$LATEST"
            },
            "lambda_handler": "main.handler",
            "lambda_settings": {
                "prod": [
                    10,
                    128
                ]
            },
            "lambda_source_bucket_name": "unit-testing.streamalert.source",
            "lambda_source_current_hash": "auto",
            "lambda_source_key": "auto",
            "flow_log_settings": {},
            "output_lambda_current_hash": "auto",
            "output_lambda_source_key": "auto",
            "prefix": "unit-testing",
            "region": "us-east-1",
            "tfstate_s3_key": "stream_alert_state/terraform.tfstate",
            "tfvars": "terraform.tfvars",
            "third_party_libs": [
                "jsonpath_rw",
                "netaddr"
            ]
        }

        v1_config_pretty = json.dumps(
            v1_config,
            indent=4,
            separators=(',', ': '),
            sort_keys=True
        )

        def load_config(path):
            if path == 'variables.json':
                return io.BytesIO(v1_config_pretty)

        # mock the opening of `variables.json`
        with patch('__builtin__.open') as mocked_open:
            mocked_open.side_effect = load_config
            cli_config = CLIConfig()

            assert_equal(cli_config.version, 2)
            assert_equal(cli_config['account']['aws_account_id'], '12345678911')
            assert_equal(cli_config['alert_processor_config']['source_bucket'], 
                                    'unit-testing.streamalert.source')
            assert_equal(cli_config['rule_processor_config']['third_party_libraries'],
                                    ['jsonpath_rw', 'netaddr'])
            assert_equal(cli_config['terraform']['tfstate_s3_key'],
                                    'stream_alert_state/terraform.tfstate')

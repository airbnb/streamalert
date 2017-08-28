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
from nose.tools import assert_equal, assert_true

from stream_alert_cli.config import CLIConfig
from stream_alert_cli.terraform import _common, kinesis_events

CONFIG = CLIConfig(config_path='tests/unit/conf')

def test_kinesis_events():
    """CLI - Terraform Generate Kinesis Events"""
    cluster_dict = _common.infinitedict()
    result = kinesis_events.generate_kinesis_events('advanced',
                                                    cluster_dict,
                                                    CONFIG)

    expected_result = {
        'module': {
            'kinesis_events_advanced': {
                'source': 'modules/tf_stream_alert_kinesis_events',
                'lambda_production_enabled': True,
                'lambda_role_id': '${module.stream_alert_advanced.lambda_role_id}',
                'lambda_function_arn': '${module.stream_alert_advanced.lambda_arn}',
                'kinesis_stream_arn': '${module.kinesis_advanced.arn}',
                'role_policy_prefix': 'advanced'
            }
        }
    }

    assert_true(result)
    assert_equal(cluster_dict, expected_result)

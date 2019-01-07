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
from nose.tools import assert_equal

from stream_alert_cli.config import CLIConfig
from stream_alert_cli.terraform import athena

CONFIG = CLIConfig(config_path='tests/unit/conf')

def test_generate_athena():
    """CLI - Terraform Generate Athena"""

    CONFIG['global']['infrastructure']['athena'] = {
        'buckets': {
            'unit-testing.streamalerts': 'alerts',
            'unit-testing.streamalert.data': 'data'
        },
        'timeout': '60',
        'memory': '128',
        'third_party_libraries': []
    }

    prefix = CONFIG['global']['account']['prefix']

    expected_athena_config = {
        'module': {
            'stream_alert_athena': {
                's3_logging_bucket': '{}.streamalert.s3-logging'.format(prefix),
                'source': 'modules/tf_stream_alert_athena',
                'database_name': '{}_streamalert'.format(prefix),
                'results_bucket': '{}.streamalert.athena-results'.format(prefix),
                'kms_key_id': '${aws_kms_key.server_side_encryption.key_id}',
                'prefix': 'unit-testing',
            },
        }
    }

    athena_config = athena.generate_athena(config=CONFIG)

    # Compare each generated Athena module from the expected module
    assert_equal(athena_config['module']['stream_alert_athena'],
                 expected_athena_config['module']['stream_alert_athena'])

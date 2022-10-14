"""
Copyright 2017-present Airbnb, Inc.

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

from streamalert_cli.config import CLIConfig
from streamalert_cli.terraform import athena

CONFIG = CLIConfig(config_path='tests/unit/conf')


def test_generate_athena():
    """CLI - Terraform Generate Athena Partitioner"""

    CONFIG['lambda']['athena_partitioner_config'] = {
        'timeout': 60,
        'memory': 128,
    }

    prefix = CONFIG['global']['account']['prefix']

    expected_athena_config = {
        'module': {
            'athena_partitioner_iam': {
                'source': './modules/tf_athena',
                's3_logging_bucket': f'{prefix}-streamalert-s3-logging',
                'prefix': 'unit-test',
                'account_id': '12345678910',
                'database_name': f'{prefix}_streamalert',
                'queue_name': f'{prefix}_streamalert_athena_s3_notifications',
                'results_bucket': f'{prefix}-streamalert-athena-results',
                'athena_data_buckets': [
                    '${aws_s3_bucket.streamalerts.bucket}',
                    '${module.kinesis_firehose_setup.data_bucket_name}',
                ],
                'lambda_timeout': 60,
                'kms_key_id': '${aws_kms_key.server_side_encryption.key_id}',
                'function_role_id': '${module.athena_partitioner_lambda.role_id}',
                'function_name': '${module.athena_partitioner_lambda.function_name}',
                'function_alias_arn': '${module.athena_partitioner_lambda.function_alias_arn}'},
            'athena_partitioner_lambda': {
                'description': 'Unit-Test Streamalert Athena Partitioner',
                'environment_variables': {
                    'ENABLE_METRICS': '0',
                    'LOGGER_LEVEL': 'info'},
                'tags': {
                    'Subcomponent': 'AthenaPartitioner'},
                'function_name': 'unit-test_streamalert_athena_partitioner',
                'handler': 'streamalert.athena_partitioner.main.handler',
                'memory_size_mb': 128,
                'source': './modules/tf_lambda',
                'timeout_sec': 60,
            }}}

    athena_config = athena.generate_athena(config=CONFIG)

    assert athena_config == expected_athena_config

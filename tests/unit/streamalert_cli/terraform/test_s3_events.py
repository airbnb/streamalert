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
from mock import patch
from nose.tools import assert_equal

from streamalert_cli.config import CLIConfig
from streamalert_cli.terraform import common, s3_events

CONFIG = CLIConfig(config_path='tests/unit/conf')


def test_generate_s3_events():
    """CLI - Terraform - S3 Events"""
    cluster_dict = common.infinitedict()
    result = s3_events.generate_s3_events('advanced', cluster_dict, CONFIG)

    expected_config = {
        'module': {
            's3_events_unit-test_advanced_unit-test-bucket.data': {
                'source': './modules/tf_s3_events',
                'lambda_function_alias': (
                    '${module.classifier_advanced_lambda.function_alias}'
                ),
                'lambda_function_alias_arn': (
                    '${module.classifier_advanced_lambda.function_alias_arn}'
                ),
                'lambda_function_name': (
                    '${module.classifier_advanced_lambda.function_name}'
                ),
                'bucket_name': 'unit-test-bucket.data',
                'lambda_role_id': '${module.classifier_advanced_lambda.role_id}',
                'filters': [
                    {
                        'filter_prefix': 'AWSLogs/123456789/CloudTrail/us-east-1/',
                        'filter_suffix': '.log'
                    }
                ]
            },
            's3_events_unit-test_advanced_unit-test.cloudtrail.data': {
                'source': './modules/tf_s3_events',
                'lambda_function_alias': (
                    '${module.classifier_advanced_lambda.function_alias}'
                ),
                'lambda_function_alias_arn': (
                    '${module.classifier_advanced_lambda.function_alias_arn}'
                ),
                'lambda_function_name': (
                    '${module.classifier_advanced_lambda.function_name}'
                ),
                'bucket_name': 'unit-test.cloudtrail.data',
                'lambda_role_id': '${module.classifier_advanced_lambda.role_id}',
                'filters': []
            }
        }
    }

    assert_equal(result, True)
    assert_equal(cluster_dict, expected_config)

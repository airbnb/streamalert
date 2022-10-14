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
from streamalert_cli.terraform import common, s3_events

CONFIG = CLIConfig(config_path='tests/unit/conf')


def test_generate_s3_events():
    """CLI - Terraform - S3 Events, No Module Prefix"""
    cluster_dict = common.infinitedict()
    result = s3_events.generate_s3_events('advanced', cluster_dict, CONFIG)

    expected_config = {
        'module': {
            's3_events_unit-test_advanced_unit-test-bucket_data': {
                'source': './modules/tf_s3_events',
                'lambda_function_alias': '${module.classifier_advanced_lambda.function_alias}',
                'lambda_function_alias_arn': (
                    '${module.classifier_advanced_lambda.function_alias_arn}'
                ),
                'lambda_function_name': '${module.classifier_advanced_lambda.function_name}',
                'bucket_name': 'unit-test-bucket.data',
                'lambda_role_id': '${module.classifier_advanced_lambda.role_id}',
                'filters': [
                    {
                        'filter_prefix': 'AWSLogs/123456789/CloudTrail/us-east-1/',
                        'filter_suffix': '.log'
                    }
                ]
            },
            's3_events_unit-test_advanced_unit-test_cloudtrail_data': {
                'source': './modules/tf_s3_events',
                'lambda_function_alias': '${module.classifier_advanced_lambda.function_alias}',
                'lambda_function_alias_arn': (
                    '${module.classifier_advanced_lambda.function_alias_arn}'
                ),
                'lambda_function_name': '${module.classifier_advanced_lambda.function_name}',
                'bucket_name': 'unit-test.cloudtrail.data',
                'lambda_role_id': '${module.classifier_advanced_lambda.role_id}',
                'filters': []
            }
        }
    }

    assert result
    assert cluster_dict == expected_config


def test_generate_s3_events_with_prefix():
    """CLI - Terraform - S3 Events, With Module Prefix"""
    cluster_dict = common.infinitedict()
    bucket_config = {
        'unit-test-bucket': [
            {
                'filter_prefix': 'AWSLogs/123456789/CloudTrail/us-east-1/',
            }
        ]
    }
    s3_events.generate_s3_events_by_bucket(
        'advanced',
        cluster_dict,
        CONFIG,
        bucket_config,
        module_prefix='cloudtrail'
    )

    expected_config = {
        'module': {
            'cloudtrail_s3_events_unit-test_advanced_unit-test-bucket': {
                'source': './modules/tf_s3_events',
                'lambda_function_alias': '${module.classifier_advanced_lambda.function_alias}',
                'lambda_function_alias_arn': (
                    '${module.classifier_advanced_lambda.function_alias_arn}'
                ),
                'lambda_function_name': '${module.classifier_advanced_lambda.function_name}',
                'bucket_name': 'unit-test-bucket',
                'lambda_role_id': '${module.classifier_advanced_lambda.role_id}',
                'filters': [
                    {
                        'filter_prefix': 'AWSLogs/123456789/CloudTrail/us-east-1/'
                    }
                ]
            },
        }
    }

    assert cluster_dict == expected_config

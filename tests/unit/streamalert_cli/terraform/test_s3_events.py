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
from nose.tools import assert_equal, assert_false, assert_true

from streamalert_cli.config import CLIConfig
from streamalert_cli.terraform import common, s3_events

CONFIG = CLIConfig(config_path='tests/unit/conf')


def test_generate_s3_events_legacy():
    """CLI - Terraform - S3 Events - Legacy"""
    cluster_dict = common.infinitedict()
    CONFIG['clusters']['test']['modules']['s3_events'] = {
        's3_bucket_id': 'unit-test-bucket.legacy.data'
    }
    result = s3_events.generate_s3_events('test', cluster_dict, CONFIG)

    assert_true(result)
    assert_equal(CONFIG['clusters']['test']['modules']['s3_events'],
                 [{
                     'bucket_id': 'unit-test-bucket.legacy.data'
                 }])


def test_generate_s3_events():
    """CLI - Terraform - S3 Events with Valid Buckets"""
    cluster_dict = common.infinitedict()
    result = s3_events.generate_s3_events('advanced', cluster_dict, CONFIG)

    expected_config = {
        'module': {
            's3_events_unit-test_advanced_0': {
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
                'bucket_id': 'unit-test-bucket.data',
                'notification_id': 'advanced_0',
                'enable_events': True,
                'lambda_role_id': '${module.classifier_advanced_lambda.role_id}',
                'filter_suffix': '.log',
                'filter_prefix': 'AWSLogs/123456789/CloudTrail/us-east-1/'
            },
            's3_events_unit-test_advanced_1': {
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
                'bucket_id': 'unit-test.cloudtrail.data',
                'enable_events': False,
                'notification_id': 'advanced_1',
                'lambda_role_id': '${module.classifier_advanced_lambda.role_id}',
                'filter_suffix': '',
                'filter_prefix': ''
            }
        }
    }

    assert_true(result)
    assert_equal(cluster_dict, expected_config)


@patch('streamalert_cli.terraform.s3_events.LOGGER')
def test_generate_s3_events_invalid_bucket(mock_logging):
    """CLI - Terraform - S3 Events with Missing Bucket Key"""
    cluster_dict = common.infinitedict()
    CONFIG['clusters']['advanced']['modules']['s3_events'] = [{'wrong_key': 'my-bucket!!!'}]
    result = s3_events.generate_s3_events('advanced', cluster_dict, CONFIG)

    assert_true(mock_logging.error.called)
    assert_false(result)

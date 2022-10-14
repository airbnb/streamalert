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
from unittest.mock import patch

from streamalert_cli.config import CLIConfig
from streamalert_cli.terraform import common, monitoring

CONFIG = CLIConfig(config_path='tests/unit/conf')


def test_generate_cloudwatch_monitoring():
    """CLI - Terraform Generate Cloudwatch Monitoring"""
    cluster_dict = common.infinitedict()
    result = monitoring.generate_monitoring('test', cluster_dict, CONFIG)

    # Test the default SNS topic option
    expected_cloudwatch_tf = {
        'source': './modules/tf_monitoring',
        'sns_topic_arn': 'arn:aws:sns:us-west-1:12345678910:unit-test_streamalert_monitoring',
        'lambda_functions': ['unit-test_test_streamalert_classifier'],
        'kinesis_stream': '${module.kinesis_test.stream_name}',
        'lambda_alarms_enabled': True,
        'kinesis_alarms_enabled': True
    }

    assert result
    assert (
        cluster_dict['module']['cloudwatch_monitoring_test'] ==
        expected_cloudwatch_tf)


def test_generate_cloudwatch_monitoring_with_settings():
    """CLI - Terraform Generate Cloudwatch Monitoring with Custom Settings"""
    cluster_dict = common.infinitedict()
    result = monitoring.generate_monitoring('advanced', cluster_dict, CONFIG)

    # Test the default SNS topic option
    expected_cloudwatch_tf = {
        'source': './modules/tf_monitoring',
        'sns_topic_arn': 'arn:aws:sns:us-west-1:12345678910:unit-test_streamalert_monitoring',
        'lambda_functions': ['unit-test_advanced_streamalert_classifier'],
        'kinesis_stream': '${module.kinesis_advanced.stream_name}',
        'lambda_alarms_enabled': True,
        'kinesis_alarms_enabled': True,
        'kinesis_iterator_age_error_threshold': '3000000'
    }

    assert result
    assert (
        cluster_dict['module']['cloudwatch_monitoring_advanced'] ==
        expected_cloudwatch_tf)


def test_generate_cloudwatch_monitoring_disabled():
    """CLI - Terraform Generate Cloudwatch Monitoring Disabled"""
    cluster_dict = common.infinitedict()
    cluster = 'trusted'
    result = monitoring.generate_monitoring(cluster, cluster_dict, CONFIG)

    assert result
    assert f'cloudwatch_monitoring_{cluster}' not in cluster_dict['module']


def test_generate_cloudwatch_monitoring_no_kinesis():
    """CLI - Terraform Generate Cloudwatch Monitoring - Kinesis Disabled"""
    cluster_dict = common.infinitedict()
    CONFIG['clusters']['test']['modules']['cloudwatch_monitoring']['kinesis_alarms_enabled'] = False
    CONFIG['clusters']['test']['modules']['cloudwatch_monitoring']['lambda_alarms_enabled'] = True
    result = monitoring.generate_monitoring('test', cluster_dict, CONFIG)

    # Test the default SNS topic option
    expected_cloudwatch_tf = {
        'source': './modules/tf_monitoring',
        'sns_topic_arn': 'arn:aws:sns:us-west-1:12345678910:unit-test_streamalert_monitoring',
        'lambda_functions': ['unit-test_test_streamalert_classifier'],
        'lambda_alarms_enabled': True,
        'kinesis_alarms_enabled': False
    }

    assert result
    assert (
        cluster_dict['module']['cloudwatch_monitoring_test'] ==
        expected_cloudwatch_tf)


def test_generate_cloudwatch_monitoring_no_lambda():
    """CLI - Terraform Generate Cloudwatch Monitoring - Lambda Disabled"""
    cluster_dict = common.infinitedict()
    CONFIG['clusters']['test']['modules']['cloudwatch_monitoring']['lambda_alarms_enabled'] = False
    CONFIG['clusters']['test']['modules']['cloudwatch_monitoring']['kinesis_alarms_enabled'] = True
    result = monitoring.generate_monitoring('test', cluster_dict, CONFIG)

    # Test the default SNS topic option
    expected_cloudwatch_tf = {
        'source': './modules/tf_monitoring',
        'sns_topic_arn': 'arn:aws:sns:us-west-1:12345678910:unit-test_streamalert_monitoring',
        'kinesis_stream': '${module.kinesis_test.stream_name}',
        'lambda_alarms_enabled': False,
        'kinesis_alarms_enabled': True
    }

    assert result
    assert (
        cluster_dict['module']['cloudwatch_monitoring_test'] ==
        expected_cloudwatch_tf)


def test_generate_cloudwatch_monitoring_custom_sns():
    """CLI - Terraform Generate Cloudwatch Monitoring with Existing SNS Topic"""

    # Test a custom SNS topic name
    CONFIG['clusters']['test']['modules']['cloudwatch_monitoring'] = {'enabled': True}
    CONFIG['global']['infrastructure']['monitoring']['sns_topic_name'] = 'unit_test_monitoring'

    cluster_dict = common.infinitedict()
    result = monitoring.generate_monitoring('test', cluster_dict, CONFIG)

    expected_cloudwatch_tf_custom = {
        'source': './modules/tf_monitoring',
        'sns_topic_arn': 'arn:aws:sns:us-west-1:12345678910:unit_test_monitoring',
        'lambda_functions': ['unit-test_test_streamalert_classifier'],
        'kinesis_stream': '${module.kinesis_test.stream_name}',
        'lambda_alarms_enabled': True,
        'kinesis_alarms_enabled': True
    }

    assert result
    assert (
        cluster_dict['module']['cloudwatch_monitoring_test'] ==
        expected_cloudwatch_tf_custom)


@patch('streamalert_cli.terraform.monitoring.LOGGER')
def test_generate_cloudwatch_monitoring_invalid_config(mock_logging):
    """CLI - Terraform Generate Cloudwatch Monitoring with Invalid Config"""
    CONFIG['global']['infrastructure'] = {}

    cluster_dict = common.infinitedict()
    result = monitoring.generate_monitoring('test', cluster_dict, CONFIG)

    assert mock_logging.error.called
    assert not result

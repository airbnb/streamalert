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

from stream_alert_cli.config import CLIConfig
from stream_alert_cli.terraform import _common, monitoring

CONFIG = CLIConfig(config_path='tests/unit/conf')

def test_generate_cloudwatch_monitoring():
    """CLI - Terraform Generate Cloudwatch Monitoring"""
    cluster_dict = _common.infinitedict()
    result = monitoring.generate_monitoring('test',
                                            cluster_dict,
                                            CONFIG)

    # Test a the default SNS topic option
    expected_cloudwatch_tf = {
        'source': 'modules/tf_stream_alert_monitoring',
        'sns_topic_arn': 'arn:aws:sns:us-west-1:12345678910:stream_alert_monitoring',
        'lambda_functions': [
            'unit-testing_test_streamalert_rule_processor',
            'unit-testing_test_streamalert_alert_processor'
        ],
        'kinesis_stream': 'unit-testing_test_stream_alert_kinesis'
    }

    assert_true(result)
    assert_equal(
        cluster_dict['module']['cloudwatch_monitoring_test'],
        expected_cloudwatch_tf)

def test_generate_cloudwatch_monitoring_custom_sns():
    """CLI - Terraform Generate Cloudwatch Monitoring with Existing SNS Topic"""

    # Test a custom SNS topic name
    CONFIG['global']['infrastructure']['monitoring']['create_sns_topic'] = False
    CONFIG['global']['infrastructure']['monitoring']\
          ['sns_topic_name'] = 'unit_test_monitoring'

    cluster_dict = _common.infinitedict()
    result = monitoring.generate_monitoring('test',
                                            cluster_dict,
                                            CONFIG)

    expected_cloudwatch_tf_custom = {
        'source': 'modules/tf_stream_alert_monitoring',
        'sns_topic_arn': 'arn:aws:sns:us-west-1:12345678910:unit_test_monitoring',
        'lambda_functions': [
            'unit-testing_test_streamalert_rule_processor',
            'unit-testing_test_streamalert_alert_processor'
        ],
        'kinesis_stream': 'unit-testing_test_stream_alert_kinesis'
    }

    assert_true(result)
    assert_equal(
        cluster_dict['module']['cloudwatch_monitoring_test'],
        expected_cloudwatch_tf_custom)

@patch('stream_alert_cli.terraform.monitoring.LOGGER_CLI')
def test_generate_cloudwatch_monitoring_invalid_config(mock_logging):
    """CLI - Terraform Generate Cloudwatch Monitoring with Invalid Config"""
    CONFIG['global']['infrastructure'] = {}

    cluster_dict = _common.infinitedict()
    result = monitoring.generate_monitoring('test',
                                            cluster_dict,
                                            CONFIG)

    assert_true(mock_logging.error.called)
    assert_false(result)

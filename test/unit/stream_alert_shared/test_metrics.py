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
from mock import Mock, patch

from botocore.exceptions import ClientError

from stream_alert.shared.metrics import Metrics

from unit.stream_alert_rule_processor import REGION


class TestMetrics(object):
    """Test class for Metrics class"""

    def __init__(self):
        self.__metrics = None

    def setup(self):
        """Setup before each method"""
        self.__metrics = Metrics(REGION)

    def teardown(self):
        """Teardown after each method"""
        self.__metrics = None

    @patch('logging.Logger.error')
    def test_invalid_metric_name(self, log_mock):
        """Metrics - Invalid Name"""
        self.__metrics.add_metric('bad metric name', 100, 'Seconds')

        log_mock.assert_called_with('Metric name not defined: %s', 'bad metric name')

    @patch('logging.Logger.error')
    def test_invalid_metric_unit(self, log_mock):
        """Metrics - Invalid Unit Type"""
        self.__metrics.add_metric('RuleProcessorFailedParses', 100, 'Total')

        log_mock.assert_called_with('Metric unit not defined: %s', 'Total')

    @patch('stream_alert.shared.metrics.Metrics._put_metrics')
    def test_valid_metric(self, metric_mock):
        """Metrics - Valid Metric"""
        self.__metrics.add_metric('RuleProcessorFailedParses', 100, 'Count')
        self.__metrics.send_metrics()

        metric_mock.assert_called()

    @patch('logging.Logger.exception')
    def test_boto_failed(self, log_mock):
        """Metrics - Boto Call Failed"""
        self.__metrics.boto_cloudwatch = Mock()

        err_response = {'Error': {'Code': 100}}

        # Add ClientError side_effect to mock
        self.__metrics.boto_cloudwatch.put_metric_data.side_effect = ClientError(
            err_response, 'operation')

        self.__metrics._metric_data.append({'test': 'info'})
        self.__metrics._put_metrics()

        log_mock.assert_called_with(
            'Failed to send metric to CloudWatch. Error: %s\nMetric data:\n%s',
            err_response,
            '[\n  {\n    "test": "info"\n  }\n]')

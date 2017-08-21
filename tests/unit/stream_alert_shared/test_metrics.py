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
# pylint: disable=no-self-use,protected-access
import os

from botocore.exceptions import ClientError
from mock import call, Mock, patch
from nose.tools import assert_equal

import stream_alert.shared as shared
from tests.unit.stream_alert_rule_processor import REGION


class TestMetrics(object):
    """Test class for Metrics class"""

    def __init__(self):
        self.__metrics = None

    def setup(self):
        """Setup before each method"""
        self.__metrics = shared.metrics.Metrics('TestFunction', REGION)

    def teardown(self):
        """Teardown after each method"""
        self.__metrics = None
        if 'ENABLE_METRICS' in os.environ:
            del os.environ['ENABLE_METRICS']

        if 'LOGGER_LEVEL' in os.environ:
            del os.environ['LOGGER_LEVEL']

    @patch('logging.Logger.error')
    def test_invalid_metric_name(self, log_mock):
        """Metrics - Invalid Name"""
        self.__metrics.add_metric('bad metric name', 100, 'Seconds')

        log_mock.assert_called_with('Metric name not defined: %s', 'bad metric name')

    @patch('logging.Logger.error')
    def test_invalid_metric_unit(self, log_mock):
        """Metrics - Invalid Unit Type"""
        self.__metrics.add_metric('FailedParses', 100, 'Total')

        log_mock.assert_called_with('Metric unit not defined: %s', 'Total')

    @patch('stream_alert.shared.metrics.Metrics._put_metrics')
    def test_valid_metric(self, metric_mock):
        """Metrics - Valid Metric"""
        # Enable the metrics
        os.environ['ENABLE_METRICS'] = '1'

        # Force reload the metrics package to trigger constant loading
        reload(shared.metrics)

        self.__metrics.add_metric('FailedParses', 100, 'Count')
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

    @patch('logging.Logger.debug')
    def test_no_metrics_to_send(self, log_mock):
        """Metrics - No Metrics To Send"""
        # Enable the metrics
        os.environ['ENABLE_METRICS'] = '1'

        # Force reload the metrics package to trigger constant loading
        reload(shared.metrics)

        self.__metrics.send_metrics()

        log_mock.assert_called_with('No metric data to send to CloudWatch.')

    @patch('logging.Logger.debug')
    def test_disabled_metrics(self, log_mock):
        """Metrics - Metrics Disabled"""
        self.__metrics.send_metrics()

        log_mock.assert_called_with('Sending of metric data is currently disabled.')

    @patch('logging.Logger.error')
    def test_disabled_metrics_error(self, log_mock):
        """Metrics - Bad Boolean Value"""
        os.environ['ENABLE_METRICS'] = 'bad'

        # Force reload the metrics package to trigger constant loading
        reload(shared.metrics)

        log_mock.assert_called_with('Invalid value for metric toggling, '
                                    'expected 0 or 1: %s',
                                    'invalid literal for int() with '
                                    'base 10: \'bad\'')

    @patch('stream_alert.shared.LOGGER.error')
    def test_init_logging_bad(self, log_mock):
        """Shared Init - Logging, Bad Level"""
        level = 'IFNO'

        os.environ['LOGGER_LEVEL'] = level

        # Force reload the shared package to trigger the init
        reload(shared)

        message = str(call('Defaulting to INFO logging: %s',
                           ValueError('Unknown level: \'IFNO\'',)))

        assert_equal(str(log_mock.call_args_list[0]), message)

    @patch('stream_alert.shared.LOGGER.setLevel')
    def test_init_logging_int_level(self, log_mock):
        """Shared Init - Logging, Integer Level"""
        level = '10'

        os.environ['LOGGER_LEVEL'] = level

        # Force reload the shared package to trigger the init
        reload(shared)

        log_mock.assert_called_with(10)

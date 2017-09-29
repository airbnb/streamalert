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

from mock import call, patch
from nose.tools import assert_equal

from stream_alert import shared


class TestMetrics(object):
    """Test class for Metrics class"""

    def setup(self):
        """Setup before each method"""
        os.environ['ENABLE_METRICS'] = '1'
        # Force reload the metrics package to trigger env var loading
        reload(shared.metrics)

    @patch('logging.Logger.error')
    def test_invalid_metric_function(self, log_mock):
        """Metrics - Invalid Function Name"""
        shared.metrics.MetricLogger.log_metric('rule_procesor', '', '')

        log_mock.assert_called_with(
            'Function \'%s\' not defined in available metrics. '
            'Options are: %s', 'rule_procesor', '\'rule_processor\'')

    @patch('logging.Logger.error')
    def test_invalid_metric_name(self, log_mock):
        """Metrics - Invalid Metric Name"""
        shared.metrics.MetricLogger.log_metric('rule_processor', 'FailedParsed', '')

        assert_equal(log_mock.call_args[0][0], 'Metric name (\'%s\') not defined for '
                                               '\'%s\' function. Options are: %s')
        assert_equal(log_mock.call_args[0][1], 'FailedParsed')
        assert_equal(log_mock.call_args[0][2], 'rule_processor')

    @patch('logging.Logger.info')
    def test_valid_metric(self, log_mock):
        """Metrics - Valid Metric"""
        shared.metrics.MetricLogger.log_metric('rule_processor', 'FailedParses', 100)

        log_mock.assert_called_with('{"metric_name": "%s", "metric_value": %s}',
                                    'FailedParses', 100)

    @patch('logging.Logger.debug')
    def test_disabled_metrics(self, log_mock):
        """Metrics - Metrics Disabled"""
        with patch.dict('os.environ', {'ENABLE_METRICS': '0'}):
            # Force reload the metrics package to trigger constant loading
            reload(shared.metrics)

            log_mock.assert_called_with('Logging of metric data is currently disabled.')

    @patch('logging.Logger.error')
    def test_disabled_metrics_error(self, log_mock):
        """Metrics - Bad Boolean Value"""
        with patch.dict('os.environ', {'ENABLE_METRICS': 'bad'}):
            # Force reload the metrics package to trigger constant loading
            reload(shared.metrics)

            log_mock.assert_called_with('Invalid value for metric toggling, '
                                        'expected 0 or 1: %s',
                                        'invalid literal for int() with '
                                        'base 10: \'bad\'')

    @patch('logging.Logger.error')
    def test_init_logging_bad(self, log_mock):
        """Shared Init - Logging, Bad Level"""
        with patch.dict('os.environ', {'LOGGER_LEVEL': 'IFNO'}):
            # Force reload the shared package to trigger the init
            reload(shared)

            message = str(call('Defaulting to INFO logging: %s',
                               ValueError('Unknown level: \'IFNO\'',)))

            assert_equal(str(log_mock.call_args_list[0]), message)

    @patch('logging.Logger.setLevel')
    def test_init_logging_int_level(self, log_mock):
        """Shared Init - Logging, Integer Level"""
        with patch.dict('os.environ', {'LOGGER_LEVEL': '10'}):
            # Force reload the shared package to trigger the init
            reload(shared)

            log_mock.assert_called_with(10)

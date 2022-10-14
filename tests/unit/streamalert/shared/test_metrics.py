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
import importlib
# pylint: disable=no-self-use,protected-access
import os
from unittest.mock import ANY, patch

from streamalert import shared


class TestMetrics:
    """Test class for Metrics class"""

    def setup(self):
        """Setup before each method"""
        os.environ['ENABLE_METRICS'] = '1'
        # Force reload the metrics package to trigger env var loading
        importlib.reload(shared.metrics)

    @patch('logging.Logger.error')
    def test_invalid_metric_name(self, log_mock):
        """Metrics - Invalid Metric Name"""
        shared.metrics.MetricLogger.log_metric('classifier', 'FailedParsed', '')

        assert (log_mock.call_args[0][0] == 'Metric name (\'%s\') not defined for '
                '\'%s\' function. Options are: %s')
        assert log_mock.call_args[0][1] == 'FailedParsed'
        assert log_mock.call_args[0][2] == 'classifier'

    @patch('logging.Logger.info')
    def test_valid_metric(self, log_mock):
        """Metrics - Valid Metric"""
        shared.metrics.MetricLogger.log_metric('classifier', 'FailedParses', 100)

        log_mock.assert_called_with(
            '{"metric_name": "%s", "metric_value": %s}', 'FailedParses', 100
        )

    @patch('logging.Logger.debug')
    def test_disabled_metrics(self, log_mock):
        """Metrics - Metrics Disabled"""
        with patch.dict('os.environ', {'ENABLE_METRICS': '0'}):
            # Force reload the metrics package to trigger constant loading
            importlib.reload(shared.metrics)

            log_mock.assert_called_with('Logging of metric data is currently disabled.')

    @patch('logging.Logger.error')
    def test_disabled_metrics_error(self, log_mock):
        """Metrics - Bad Boolean Value"""
        with patch.dict('os.environ', {'ENABLE_METRICS': 'bad'}):
            # Force reload the metrics package to trigger constant loading
            importlib.reload(shared.metrics)

            log_mock.assert_called_with('Invalid value for metric toggling, '
                                        'expected 0 or 1: %s',
                                        ANY)

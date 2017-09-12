"""
Copyright 2017-present, Airbnb Inc.

Licensed under the Apache License, Version 2.0 (the 'License');
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an 'AS IS' BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
# pylint: disable=protected-access
from contextlib import nested
import json

from mock import Mock, patch
from nose.tools import assert_equal, assert_true

from stream_alert_cli.config import CLIConfig
from tests.unit.helpers.base import basic_streamalert_config, mock_open


class TestCLIConfig(object):
    """Test class for CLIConfig"""

    def __init__(self):
        self.mocked_opens = None

    def setup(self):
        """Setup before each method"""
        config_data = basic_streamalert_config()
        self.mocked_opens = [
            mock_open('conf/global.json', json.dumps(config_data['global'])),
            mock_open('conf/lambda.json', json.dumps(config_data['lambda'])),
            mock_open('conf/clusters/prod.json', json.dumps(config_data['clusters']['prod']))
        ]

    def test_load_config(self):
        """CLI - Load config"""
        with nested(*self.mocked_opens):
            config = CLIConfig()
            assert_equal(config['global']['account']['prefix'], 'unit-testing')

    @patch('logging.Logger.error')
    @patch('stream_alert_cli.config.CLIConfig.write')
    def test_toggle_metric(self, write_mock, log_mock):
        """CLI - Metric toggling"""
        with nested(*self.mocked_opens):
            config = CLIConfig()

            config.toggle_metrics(True, [], ['athena_partition_refresh'])
            write_mock.assert_called()

            del config.config['lambda']['athena_partition_refresh_config']
            config.toggle_metrics(True, [], ['athena_partition_refresh'])
            log_mock.assert_called_with('No Athena configuration found; please initialize first.')

            config.toggle_metrics(True, ['prod'], ['alert_processor'])
            write_mock.assert_called()

    def test_aggregate_alarm_exists(self):
        """CLI - Aggregate alarm check"""
        with nested(*self.mocked_opens):
            config = CLIConfig()
            result = config._alarm_exists('Aggregate Unit Testing Failed Parses Alarm')
            assert_true(result)

    def test_cluster_alarm_exists(self):
        """CLI - Aggregate alarm check"""
        with nested(*self.mocked_opens):
            config = CLIConfig()
            result = config._alarm_exists('Prod Unit Testing Failed Parses Alarm')
            assert_true(result)

    @patch('stream_alert_cli.config.CLIConfig.write', Mock())
    @patch('logging.Logger.info')
    def test_cluster_alarm_creation(self, log_mock):
        """CLI - Adding CloudWatch metric alarm, cluster"""
        alarm_info = {
            'metric_target': 'cluster',
            'metric_name': 'TotalRecords',
            'evaluation_periods': 1,
            'alarm_description': '',
            'alarm_name': 'Prod Unit Testing Total Records Alarm',
            'period': 300,
            'threshold': 100.0,
            'statistic': 'Sum',
            'clusters': set(['prod']),
            'comparison_operator': 'LessThanThreshold'
        }

        with nested(*self.mocked_opens):
            config = CLIConfig()
            config.add_metric_alarm(alarm_info)
            log_mock.assert_called_with('Successfully added \'%s\' metric alarm for the '
                                        '\'%s\' function to \'conf/clusters/%s.json\'.',
                                        'Prod Unit Testing Total Records Alarm',
                                        'rule_processor',
                                        'prod')

    @patch('stream_alert_cli.config.CLIConfig.write', Mock())
    @patch('logging.Logger.info')
    def test_aggregate_alarm_creation(self, log_mock):
        """CLI - Adding CloudWatch metric alarm, aggregate"""
        alarm_info = {
            'metric_target': 'aggregate',
            'metric_name': 'TotalRecords',
            'evaluation_periods': 1,
            'alarm_description': '',
            'alarm_name': 'Aggregate Unit Testing Total Records Alarm',
            'period': 300,
            'threshold': 100.0,
            'statistic': 'Sum',
            'clusters': {},
            'comparison_operator': 'LessThanThreshold'
        }

        with nested(*self.mocked_opens):
            config = CLIConfig()
            config.add_metric_alarm(alarm_info)
            log_mock.assert_called_with('Successfully added \'%s\' metric alarm to '
                                        '\'conf/global.json\'.',
                                        'Aggregate Unit Testing Total Records Alarm')

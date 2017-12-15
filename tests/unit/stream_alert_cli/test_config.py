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
import json

from mock import Mock, patch
from nose.tools import assert_equal, assert_true, assert_false
from pyfakefs import fake_filesystem_unittest

from stream_alert_cli.config import CLIConfig
from tests.unit.helpers.base import basic_streamalert_config


class TestCLIConfig(object):
    """Test class for CLIConfig"""

    def __init__(self):
        self.config = None
        self.fs_patcher = None

    def setup(self):
        """Setup before each method"""
        config_data = basic_streamalert_config()

        self.fs_patcher = fake_filesystem_unittest.Patcher()
        self.fs_patcher.setUp()

        self.fs_patcher.fs.CreateFile('/conf/global.json',
                                      contents=json.dumps(config_data['global']))
        self.fs_patcher.fs.CreateFile('/conf/lambda.json',
                                      contents=json.dumps(config_data['lambda']))
        self.fs_patcher.fs.CreateFile('/conf/clusters/prod.json',
                                      contents=json.dumps(config_data['clusters']['prod']))

        # Create the config instance after creating the fake filesystem so that
        # CLIConfig uses our mocked config files instead of the real ones.
        self.config = CLIConfig()

    def teardown(self):
        """Teardown after each method"""
        self.fs_patcher.tearDown()

    def test_load_config(self):
        """CLI - Load config"""
        assert_equal(self.config['global']['account']['prefix'], 'unit-testing')

    @patch('logging.Logger.error')
    @patch('stream_alert_cli.config.CLIConfig.write')
    def test_toggle_metric(self, write_mock, log_mock):
        """CLI - Metric toggling"""
        self.config.toggle_metrics(True, [], ['athena_partition_refresh'])
        write_mock.assert_called()

        del self.config.config['lambda']['athena_partition_refresh_config']
        self.config.toggle_metrics(True, [], ['athena_partition_refresh'])
        log_mock.assert_called_with('No Athena configuration found; please initialize first.')

        self.config.toggle_metrics(True, ['prod'], ['alert_processor'])
        write_mock.assert_called()

    def test_aggregate_alarm_exists(self):
        """CLI - Aggregate alarm check"""
        result = self.config._alarm_exists('Aggregate Unit Testing Failed Parses Alarm')
        assert_true(result)

    def test_cluster_alarm_exists(self):
        """CLI - Aggregate alarm check"""
        result = self.config._alarm_exists('Prod Unit Testing Failed Parses Alarm')
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

        self.config.add_metric_alarm(alarm_info)
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

        self.config.add_metric_alarm(alarm_info)
        log_mock.assert_called_with('Successfully added \'%s\' metric alarm to '
                                    '\'conf/global.json\'.',
                                    'Aggregate Unit Testing Total Records Alarm')

    @patch('logging.Logger.info')
    @patch('stream_alert_cli.config.CLIConfig.write')
    def test_add_threat_intel_with_table_name(self, write_mock, log_mock):
        """CLI - Add Threat Intel config with default dynamodb table name"""
        threat_intel_info = {
            'command': 'threat_intel',
            'debug': 'False',
            'dynamodb_table': 'my_ioc_table',
            'subcommand': 'enable'
        }

        self.config.add_threat_intel(threat_intel_info)

        expected_config = {
            'enabled': True,
            'dynamodb_table': 'my_ioc_table'
        }

        assert_equal(self.config['global']['threat_intel'], expected_config)
        write_mock.assert_called()
        log_mock.assert_called()

    @patch('logging.Logger.info')
    @patch('stream_alert_cli.config.CLIConfig.write')
    def test_add_threat_intel_without_table_name(self, write_mock, log_mock):
        """CLI - Add Threat Intel config without dynamodb table name from cli"""
        threat_intel_info = {
            'command': 'threat_intel',
            'debug': 'False',
            'subcommand': 'enable'
        }

        self.config.add_threat_intel(threat_intel_info)

        expected_config = {
            'enabled': True,
            'dynamodb_table': 'unit-testing_streamalert_threat_intel_downloader'
        }

        assert_equal(self.config['global']['threat_intel'], expected_config)
        write_mock.assert_called()
        log_mock.assert_called()

    @patch('logging.Logger.info')
    @patch('stream_alert_cli.config.CLIConfig.write')
    def test_add_threat_intel_downloader(self, write_mock, log_mock):
        """CLI - Add Threat Intel Downloader config"""
        ti_downloader_info = {
            'autoscale': True,
            'command': 'threat_intel_downloader',
            'debug': False,
            'interval': 'rate(1 day)',
            'memory': '128',
            'subcommand': 'enable',
            'timeout': '240',
            'table_wcu': 25,
            'max_read_capacity': 100,
            'min_read_capacity': 5,
            'target_utilization': 70
        }
        result = self.config.add_threat_intel_downloader(ti_downloader_info)
        assert_true(result)
        expected_config = {
            'autoscale': True,
            'enabled': True,
            'current_version': '$LATEST',
            'handler': 'stream_alert.threat_intel_downloader.main.handler',
            'interval': 'rate(1 day)',
            'ioc_filters': [],
            'ioc_keys': [],
            'ioc_types': [],
            'log_level': 'info',
            'memory': '128',
            'source_bucket': 'PREFIX_GOES_HERE.streamalert.source',
            'source_current_hash': '<auto_generated>',
            'source_object_key': '<auto_generated>',
            'third_party_libraries': [
                'requests'
            ],
            'table_rcu': 10,
            'table_wcu': 25,
            'timeout': '240',
            'max_read_capacity': 100,
            'min_read_capacity': 5,
            'target_utilization': 70
        }
        assert_equal(self.config['lambda']['threat_intel_downloader_config'], expected_config)
        write_mock.assert_called()
        log_mock.assert_not_called()

        # no config changed if threat intel downloader already been enabled via CLI
        result = self.config.add_threat_intel_downloader(ti_downloader_info)
        assert_false(result)
        write_mock.assert_called_once()
        log_mock.assert_called_with('Threat Intel Downloader has been enabled. '
                                    'Please edit config/lambda.json if you want to '
                                    'change lambda function settings.')

"""
Copyright 2017-present Airbnb, Inc.

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
from unittest.mock import Mock, patch

from pyfakefs import fake_filesystem_unittest

from streamalert_cli.config import CLIConfig
from tests.unit.helpers.config import basic_streamalert_config


class TestCLIConfig:
    """Test class for CLIConfig"""

    def __init__(self):
        self.config = None
        self.fs_patcher = None

    @patch('streamalert_cli.config.CLIConfig._copy_terraform_files', Mock())
    def setup(self):
        """Setup before each method"""
        config_data = basic_streamalert_config()

        self.fs_patcher = fake_filesystem_unittest.Patcher()
        self.fs_patcher.setUp()

        self.fs_patcher.fs.create_file(
            './conf/global.json', contents=json.dumps(config_data['global']))
        self.fs_patcher.fs.create_file(
            './conf/threat_intel.json', contents=json.dumps(config_data['threat_intel']))
        self.fs_patcher.fs.create_file(
            './conf/normalized_types.json', contents=json.dumps(config_data['normalized_types']))
        self.fs_patcher.fs.create_file(
            './conf/lambda.json', contents=json.dumps(config_data['lambda']))
        self.fs_patcher.fs.create_file(
            './conf/clusters/prod.json', contents=json.dumps(config_data['clusters']['prod']))

        # Create the config instance after creating the fake filesystem so that
        # CLIConfig uses our mocked config files instead of the real ones.
        self.config = CLIConfig('./conf/')

    def teardown(self):
        """Teardown after each method"""
        self.fs_patcher.tearDown()

    def test_load_config(self):
        """CLI - Load config"""
        assert self.config['global']['account']['prefix'] == 'unit-test'

    def test_terraform_files(self):
        """CLI - Terraform Files"""
        assert self.config.terraform_files == {'/test/terraform/file.tf'}

    def test_toggle_metric(self):
        """CLI - Metric toggling"""
        self.config.toggle_metrics('athena_partitioner', enabled=True)
        assert (
            self.config['lambda']['athena_partitioner_config']['enable_custom_metrics'] ==
            True)

        self.config.toggle_metrics('alert_processor', enabled=False)
        assert (
            self.config['lambda']['alert_processor_config']['enable_custom_metrics'] ==
            False)

    def test_aggregate_alarm_exists(self):
        """CLI - Aggregate alarm check"""
        result = self.config._alarm_exists('Aggregate Unit Testing Failed Parses Alarm')
        assert result

    def test_cluster_alarm_exists(self):
        """CLI - Cluster alarm check"""
        result = self.config._alarm_exists('Prod Unit Testing Failed Parses Alarm')
        assert result

    def test_cluster_alarm_creation(self):
        """CLI - Adding CloudWatch metric alarm, cluster"""
        alarm_info = {
            'function': 'classifier',
            'metric_name': 'TotalRecords',
            'evaluation_periods': 1,
            'alarm_description': '',
            'alarm_name': 'Prod Unit Testing Total Records Alarm',
            'period': 300,
            'threshold': 100.0,
            'statistic': 'Sum',
            'clusters': {'prod'},
            'comparison_operator': 'LessThanThreshold'
        }

        expected_result = {
            'Prod Unit Testing Total Records Alarm': {
                'metric_name': 'Classifier-TotalRecords-PROD',
                'evaluation_periods': 1,
                'alarm_description': '',
                'period': 300,
                'threshold': 100.0,
                'statistic': 'Sum',
                'comparison_operator': 'LessThanThreshold'
            },
            'Prod Unit Testing Failed Parses Alarm': {
                'alarm_description': '',
                'comparison_operator': 'GreaterThanOrEqualToThreshold',
                'evaluation_periods': 1,
                'metric_name': 'Classifier-FailedParses-PROD',
                'period': 300,
                'statistic': 'Sum',
                'threshold': 1.0
            }
        }

        self.config.add_metric_alarm(alarm_info)
        result = self.config['clusters']['prod']['classifier_config']['custom_metric_alarms']

        assert result == expected_result

    def test_aggregate_alarm_creation(self):
        """CLI - Adding CloudWatch metric alarm, aggregate"""
        alarm_info = {
            'function': 'classifier',
            'metric_name': 'TotalRecords',
            'evaluation_periods': 1,
            'alarm_description': '',
            'alarm_name': 'Aggregate Unit Testing Total Records Alarm',
            'period': 300,
            'threshold': 100.0,
            'statistic': 'Sum',
            'comparison_operator': 'LessThanThreshold'
        }

        expected_result = {
            'Aggregate Unit Testing Total Records Alarm': {
                'metric_name': 'Classifier-TotalRecords',
                'evaluation_periods': 1,
                'alarm_description': '',
                'period': 300,
                'threshold': 100.0,
                'statistic': 'Sum',
                'comparison_operator': 'LessThanThreshold'
            }
        }

        self.config.add_metric_alarm(alarm_info)
        result = self.config['lambda']['classifier_config']['custom_metric_alarms']

        assert result == expected_result

    def test_add_threat_intel_with_table_name(self):
        """CLI - Add Threat Intel config with default dynamodb table name"""
        threat_intel_info = {
            'command': 'threat-intel',
            'debug': 'False',
            'dynamodb_table_name': 'my_ioc_table',
            'enable': True
        }

        self.config.add_threat_intel(threat_intel_info)

        expected_config = {
            'enabled': True,
            'dynamodb_table_name': 'my_ioc_table',
            'excluded_iocs': {},
            'normalized_ioc_types': {
                'ip': [
                    'sourceAddress',
                    'destinationAddress'
                ]
            }
        }

        assert self.config['threat_intel'] == expected_config

    def test_add_threat_intel_without_table_name(self):
        """CLI - Add Threat Intel config without dynamodb table name from cli"""
        threat_intel_info = {
            'command': 'threat-intel',
            'debug': 'False',
            'dynamodb_table_name': None,
            'enable': True
        }

        del self.config['threat_intel']['dynamodb_table_name']

        self.config.add_threat_intel(threat_intel_info)

        expected_config = {
            'enabled': True,
            'dynamodb_table_name': 'unit-test_streamalert_threat_intel_downloader',
            'excluded_iocs': {},
            'normalized_ioc_types': {
                'ip': [
                    'sourceAddress',
                    'destinationAddress'
                ]
            }
        }

        assert self.config['threat_intel'] == expected_config

    @patch('logging.Logger.info')
    @patch('streamalert_cli.config.CLIConfig.write')
    def test_add_threat_intel_downloader(self, write_mock, log_mock):
        """CLI - Add Threat Intel Downloader config"""
        del self.config['lambda']['threat_intel_downloader_config']
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
        assert result
        expected_config = {
            'autoscale': True,
            'enabled': True,
            'interval': 'rate(1 day)',
            'ioc_filters': [],
            'ioc_keys': [],
            'ioc_types': [],
            'excluded_sub_types': [],
            'log_level': 'info',
            'memory': '128',
            'table_rcu': 10,
            'table_wcu': 25,
            'timeout': '240',
            'max_read_capacity': 100,
            'min_read_capacity': 5,
            'target_utilization': 70
        }
        assert self.config['lambda']['threat_intel_downloader_config'] == expected_config
        write_mock.assert_called()
        log_mock.assert_not_called()

        # no config changed if threat intel downloader already been enabled via CLI
        result = self.config.add_threat_intel_downloader(ti_downloader_info)
        assert not result
        write_mock.assert_called_once()
        log_mock.assert_called_with('Threat Intel Downloader has been enabled. '
                                    'Please edit config/lambda.json if you want to '
                                    'change lambda function settings.')

"""Test ./manage.py lambda rollback functionality."""
import unittest

from mock import call, patch
from nose.tools import assert_equal

from stream_alert_cli.manage_lambda import rollback
from tests.unit.helpers.base import basic_streamalert_config, MockCLIConfig


class MockOptions(object):
    """Simple mock for the options parsed from the command line arguments."""

    def __init__(self, clusters, processor):
        self.clusters = clusters
        self.processor = processor


@patch.object(rollback, 'LOGGER_CLI')
@patch.object(rollback, 'terraform_generate', return_value=True)
@patch.object(rollback.helpers, 'tf_runner')
class RollbackTest(unittest.TestCase):
    """Test the config updates and Terraform targets affected during a Lambda rollback."""

    def setUp(self):
        self.config = MockCLIConfig(config=basic_streamalert_config())

        # Find all function config sections (with 'current_version')
        self.alert_merger_config = self.config['lambda']['alert_merger_config']
        self.alert_config = self.config['lambda']['alert_processor_config']
        self.apps_config_box = (
            self.config['clusters']['corp']['modules']['stream_alert_apps']
            ['unit-testing_corp_box_admin_events_box_collector_app'])
        self.apps_config_duo = (
            self.config['clusters']['corp']['modules']['stream_alert_apps']
            ['unit-testing_corp_duo_admin_duo_admin_collector_app'])
        self.athena_config = self.config['lambda']['athena_partition_refresh_config']
        self.downloader_config = self.config['lambda']['threat_intel_downloader_config']
        self.rule_config_prod = (
            self.config['clusters']['prod']['modules']['stream_alert']['rule_processor'])
        self.rule_config_corp = (
            self.config['clusters']['corp']['modules']['stream_alert']['rule_processor'])

        self.func_configs = [
            self.alert_merger_config, self.alert_config, self.apps_config_box, self.apps_config_duo,
            self.athena_config, self.downloader_config, self.rule_config_prod, self.rule_config_corp
        ]

    def test_rollback_all(self, mock_runner, mock_generate, mock_logger):
        """CLI - Lambda Rollback all"""
        options = MockOptions(None, ['all'])

        for config in self.func_configs:
            config['current_version'] = 3

        rollback.rollback(options, self.config)

        # Verify that all of the versions were rolled back
        for config in self.func_configs:
            assert_equal(config['current_version'], 2)

        mock_logger.assert_not_called()
        mock_generate.assert_called_once_with(config=self.config)
        mock_runner.assert_called_once_with(targets=[
            'module.alert_merger_lambda',
            'module.alert_processor_lambda',
            'module.app_box_collector_corp',
            'module.app_duo_admin_collector_corp',
            'module.stream_alert_athena',
            'module.stream_alert_corp',
            'module.stream_alert_prod',
            'module.threat_intel_downloader'
        ])

    def test_rollback_all_invalid(self, mock_runner, mock_generate, mock_logger):
        """CLI - Lambda Rollback all invalid"""
        options = MockOptions(None, ['all'])

        # Versions $LATEST and 1 cannot be rolled back.
        self.alert_config['current_version'] = 1
        rollback.rollback(options, self.config)

        fmt = '%s cannot be rolled back from version %s'
        mock_logger.assert_has_calls([
            call.warn(fmt, 'alert_merger', '$LATEST'),
            call.warn(fmt, 'alert_processor', '1'),
            call.warn(fmt, 'unit-testing_corp_duo_admin_duo_admin_collector_app', '$LATEST'),
            call.warn(fmt, 'unit-testing_corp_box_admin_events_box_collector_app', '$LATEST'),
            call.warn(fmt, 'athena_partition_refresh', '$LATEST'),
            call.warn(fmt, 'rule_processor_prod', '$LATEST'),
            call.warn(fmt, 'rule_processor_corp', '$LATEST'),
            call.warn(fmt, 'threat_intel_downloader_config', '$LATEST')
        ], any_order=True)

        # We should have returned early - no Terraform actions necessary
        mock_generate.assert_not_called()
        mock_runner.assert_not_called()

    def test_rollback_alert_processor(self, mock_runner, mock_generate, mock_logger):
        """CLI - Lambda Rollback global alert processor"""
        options = MockOptions(None, ['alert'])
        self.alert_config['current_version'] = 5

        rollback.rollback(options, self.config)

        assert_equal(4, self.alert_config['current_version'])
        mock_logger.assert_not_called()
        mock_generate.assert_called_once_with(config=self.config)
        mock_runner.assert_called_once_with(targets=['module.alert_processor_lambda'])

    def test_rollback_rule_single_cluster(self, mock_runner, mock_generate, mock_logger):
        """CLI - Lambda Rollback rule processor in one cluster"""
        options = MockOptions(['prod'], ['rule'])

        self.rule_config_corp['current_version'] = 2
        self.rule_config_prod['current_version'] = 2

        rollback.rollback(options, self.config)

        # Only the prod rule processor should have been rolled back
        assert_equal(2, self.rule_config_corp['current_version'])
        assert_equal(1, self.rule_config_prod['current_version'])

        mock_logger.assert_not_called()
        mock_generate.assert_called_once_with(config=self.config)
        mock_runner.assert_called_once_with(targets=['module.stream_alert_prod'])

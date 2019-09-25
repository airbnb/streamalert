"""Test ./manage.py lambda rollback functionality."""
# pylint: disable=no-self-use,protected-access
import unittest

from botocore.exceptions import ClientError
import mock
from nose.tools import assert_equal

from streamalert_cli.manage_lambda import rollback
from tests.unit.helpers.config import basic_streamalert_config, MockCLIConfig


class MockOptions:
    """Simple mock for the options parsed from the command line arguments."""

    def __init__(self, clusters, function):
        self.clusters = clusters
        self.function = function


@mock.patch.object(rollback, 'boto3', mock.MagicMock())
class RollbackTest(unittest.TestCase):
    """Test the config updates and Terraform targets affected during a Lambda rollback."""

    @mock.patch.object(rollback, 'LOGGER')
    def test_rollback_production_latest(self, mock_logger):
        """CLI - Can't rollback a function at $LATEST"""
        mock_client = mock.MagicMock()
        mock_client.get_alias.return_value = {'FunctionVersion': '$LATEST'}

        rollback._rollback_production(mock_client, 'test_function')

        mock_logger.error.assert_called_once()
        mock_client.update_alias.assert_not_called()

    @mock.patch.object(rollback, 'LOGGER')
    def test_rollback_production_one(self, mock_logger):
        """CLI - Can't rollback a function at version 1"""
        mock_client = mock.MagicMock()
        mock_client.get_alias.return_value = {'FunctionVersion': '1'}

        rollback._rollback_production(mock_client, 'test_function')

        mock_logger.warning.assert_called_once()
        mock_client.update_alias.assert_not_called()

    @mock.patch.object(rollback, 'LOGGER')
    def test_rollback_production_error(self, mock_logger):
        """CLI - Exception when rolling back alias"""
        mock_client = mock.MagicMock()
        mock_client.get_alias.return_value = {'FunctionVersion': '3'}
        mock_client.update_alias.side_effect = ClientError({}, None)

        rollback._rollback_production(mock_client, 'test_function')

        mock_logger.assert_has_calls([
            mock.call.info('Rolling back %s:production from version %d => %d',
                           'test_function', 3, 2),
            mock.call.exception('version not updated')
        ])

    @mock.patch.object(rollback, 'terraform_generate_handler', mock.Mock())
    @mock.patch.object(rollback, '_rollback_production')
    def test_rollback_all(self, mock_helper):
        """CLI - Lambda rollback all"""
        mock_helper.return_value = True
        assert_equal(
            rollback.RollbackCommand.handler(
                MockOptions(None, ['all']),
                MockCLIConfig(config=basic_streamalert_config())
            ),
            True
        )
        mock_helper.assert_has_calls([
            mock.call(mock.ANY, 'unit-test_streamalert_alert_processor'),
            mock.call(mock.ANY, 'unit-test_streamalert_alert_merger'),
            mock.call(mock.ANY, 'unit-test_corp_box_admin_events_box_collector_app'),
            mock.call(mock.ANY, 'unit-test_corp_duo_admin_duo_admin_collector_app'),
            mock.call(mock.ANY, 'unit-test_streamalert_athena_partition_refresh'),
            mock.call(mock.ANY, 'unit-test_corp_streamalert_classifier'),
            mock.call(mock.ANY, 'unit-test_prod_streamalert_classifier'),
            mock.call(mock.ANY, 'unit-test_streamalert_rules_engine'),
            mock.call(mock.ANY, 'unit-test_streamalert_threat_intel_downloader')
        ])

    @mock.patch.object(rollback, 'terraform_generate_handler', mock.Mock())
    @mock.patch.object(rollback, '_rollback_production')
    def test_rollback_subset(self, mock_helper):
        """CLI - Lambda rollback apps and rule"""
        mock_helper.return_value = True
        assert_equal(
            rollback.RollbackCommand.handler(
                MockOptions(None, ['apps', 'rule']),
                MockCLIConfig(config=basic_streamalert_config())
            ),
            True
        )
        mock_helper.assert_has_calls([
            mock.call(mock.ANY, 'unit-test_corp_box_admin_events_box_collector_app'),
            mock.call(mock.ANY, 'unit-test_corp_duo_admin_duo_admin_collector_app'),
            mock.call(mock.ANY, 'unit-test_streamalert_rules_engine')
        ])

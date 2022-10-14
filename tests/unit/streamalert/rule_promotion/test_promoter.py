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
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, PropertyMock, patch

from boto3 import client
from moto import mock_dynamodb

from streamalert.rule_promotion.promoter import RulePromoter
from streamalert.rule_promotion.statistic import StagingStatistic
from streamalert.shared import config
from streamalert.shared import rule as rule_module
from tests.unit.helpers.aws_mocks import (MockAthenaClient,
                                          setup_mock_rules_table)

_RULES_TABLE = 'unit-test_streamalert_rules'


def _mock_boto(name, **kwargs):
    """Hack to allow mocking boto3.client with moto and our own class"""
    return MockAthenaClient() if name == 'athena' else client(name, **kwargs)


class TestRulePromoter:
    """Tests for rule_promotion/promoter.py:RulePromoter"""
    # pylint: disable=protected-access

    def setup(self):
        """RulePromoter - Setup"""
        # pylint: disable=attribute-defined-outside-init
        self.dynamo_mock = mock_dynamodb()
        self.dynamo_mock.start()
        with patch('streamalert.rule_promotion.promoter.load_config') as config_mock, \
                patch('streamalert.rule_promotion.promoter.StatsPublisher', Mock()), \
                patch('boto3.client', _mock_boto), \
                patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'}):
            setup_mock_rules_table(_RULES_TABLE)
            config_mock.return_value = config.load_config('tests/unit/conf/')
            self.promoter = RulePromoter()
            self._add_fake_stats()

    def teardown(self):
        """RulePromoter - Destroy previously created rules"""
        rule_module.Rule._rules.clear()
        self.dynamo_mock.stop()

    def _add_fake_stats(self):
        """Helper function to add a few fake alert statistic objects"""
        time = datetime(year=2000, month=1, day=1, hour=1, second=1)
        self.promoter._staging_stats.update({
            'test_rule': StagingStatistic(time, time + timedelta(days=2), time, 'test_rule'),
            'test_rule_2': StagingStatistic(time, time + timedelta(days=2), time, 'test_rule_2')
        })

    @staticmethod
    def _create_local_rule_with_name(name):
        """Helper to create a fake local rule with specified name"""
        rule_module.Rule(Mock(__name__=name), logs=['fake_log_type'])

    @staticmethod
    def _mock_athena_data():
        return {
            'ResultSet': {
                'Rows': [
                    {'Data': [{'VarCharValue': 'count'}, {'VarCharValue': 'rule_name'}]},
                    {'Data': [{'VarCharValue': 'test_rule'}, {'VarCharValue': '7'}]},
                    {'Data': [{'VarCharValue': 'test_rule_2'}, {'VarCharValue': '5'}]}
                ]
            }
        }

    @patch('streamalert.shared.rule_table.RuleTable.remote_rule_info', new_callable=PropertyMock)
    def test_get_staging_info(self, table_mock):
        """RulePromoter - Get Staging Info"""
        self.promoter._staging_stats.clear()
        table_mock.return_value = {
            'test_rule': {
                'Staged': True,
                'StagedAt': 'staged_at_time',
                'StagedUntil': 'staged_until_time'
            }
        }
        assert self.promoter._get_staging_info()
        assert len(self.promoter._staging_stats) == 1

    @patch('streamalert.shared.rule_table.RuleTable.remote_rule_info', new_callable=PropertyMock)
    def test_get_staging_info_none(self, table_mock):
        """RulePromoter - Get Staging Info, None Staged"""
        self.promoter._staging_stats.clear()
        table_mock.return_value = {
            'test_rule': {
                'Staged': False,
                'StagedAt': 'staged_at_time',
                'StagedUntil': 'staged_until_time'
            }
        }
        assert self.promoter._get_staging_info() == False
        assert len(self.promoter._staging_stats) == 0

    @patch('streamalert.shared.athena.AthenaClient.query_result_paginator')
    def test_update_alert_count(self, athena_mock):
        """RulePromoter - Update Alert Count"""
        athena_mock.return_value = [self._mock_athena_data()]

        self.promoter._update_alert_count()

        assert self.promoter._staging_stats['test_rule'].alert_count == 7
        assert self.promoter._staging_stats['test_rule_2'].alert_count == 5

    @patch('streamalert.shared.rule_table.RuleTable.remote_rule_info', new_callable=PropertyMock)
    @patch('streamalert.rule_promotion.publisher.StatsPublisher.publish')
    def test_run(self, publish_mock, table_mock):
        """RulePromoter - Run"""
        self.promoter._staging_stats.clear()
        table_mock.return_value = {
            'test_rule': {
                'Staged': True,
                'StagedAt': 'staged_at_time',
                'StagedUntil': 'staged_until_time'
            }
        }

        with patch.object(self.promoter, '_update_alert_count', Mock()), \
                patch.object(self.promoter, '_promote_rules', Mock()):
            self.promoter.run(True)
            publish_mock.assert_called_with(list(self.promoter._staging_stats.values()))

    @patch('logging.Logger.debug')
    def test_run_none_staged(self, log_mock):
        """RulePromoter - Run, No Staged Rules"""
        self.promoter._staging_stats.clear()
        self.promoter.run(False)
        log_mock.assert_called_with('No staged rules to promote')

    @patch('logging.Logger.debug')
    @patch('streamalert.shared.athena.AthenaClient.query_result_paginator')
    def test_run_do_not_send_digest(self, athena_mock, log_mock):
        """RulePromoter - Run, Do Not Send Digest"""
        athena_mock.return_value = [self._mock_athena_data()]
        self.promoter.run(False)
        log_mock.assert_called_with('Staging statistics digest will not be sent')

    @patch('logging.Logger.info')
    def test_promote_rules(self, log_mock):
        """RulePromoter - Promote Rules"""
        self.promoter._staging_stats['test_rule'].alert_count = 0
        self.promoter._current_time = (
            self.promoter._staging_stats['test_rule'].staged_until + timedelta(hours=1)
        )

        self.promoter._promote_rules()
        log_mock.assert_called_with(
            'Promoting rule \'%s\' at %s', 'test_rule', datetime(2000, 1, 3, 2, 0, 1))

    def test_rules_failing_promotion(self):
        """RulePromoter - Rules Failing Promotion"""
        self.promoter._staging_stats['test_rule'].alert_count = 1
        self.promoter._staging_stats['test_rule_2'].alert_count = 0
        assert self.promoter._rules_failing_promotion == ['test_rule']

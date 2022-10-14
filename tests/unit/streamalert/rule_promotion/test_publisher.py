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
from datetime import datetime, timedelta
from unittest.mock import PropertyMock, patch

import pytest

from streamalert.rule_promotion.publisher import StatsPublisher
from streamalert.rule_promotion.statistic import StagingStatistic
from streamalert.shared import athena, config


class TestStatsPublisher:
    """Tests for rule_promotion/publisher.py:StatsPublisher"""
    # pylint: disable=protected-access

    def setup(self):
        """StatsPublisher - Setup"""
        # pylint: disable=attribute-defined-outside-init
        self.publisher = StatsPublisher(
            config=config.load_config('tests/unit/conf/'),
            athena_client=None,
            current_time=datetime(year=2000, month=1, day=1, hour=1, minute=1, second=1)
        )

    @staticmethod
    def _get_fake_stats(count=2):
        """Helper function to return fake StagingStatistics"""
        stage_time = datetime(year=2000, month=1, day=1, hour=1, minute=1, second=1)
        for i in range(count):
            stat = StagingStatistic(
                staged_at=stage_time,
                staged_until=stage_time +
                timedelta(
                    days=2),
                current_time=stage_time +
                timedelta(
                    days=1),
                rule=f'test_rule_{i}')

            stat.alert_count = i + 1
            yield stat

    def test_formatted_sns_topic_arn_default(self):
        """StatsPublisher - Format SNS Topic, Default"""
        test_config = {
            'global': {
                'account': {
                    'aws_account_id': '123456789012',
                    'prefix': 'unit-test',
                    'region': 'us-east-1'
                }
            },
            'lambda': {
                'rule_promotion_config': {}  # no digest_sns_topic here
            }
        }
        topic = self.publisher.formatted_sns_topic_arn(test_config)
        assert (
            topic ==
            'arn:aws:sns:us-east-1:123456789012:unit-test_streamalert_rule_staging_stats')

    def test_formatted_sns_topic_arn_hard_coded(self):
        """StatsPublisher - Format SNS Topic, Hard-Coded"""
        test_config = {
            'global': {
                'account': {
                    'aws_account_id': '123456789012',
                    'prefix': 'unit-test',
                    'region': 'us-east-1'
                }
            },
            'lambda': {
                'rule_promotion_config': {
                    'digest_sns_topic': 'foobar'  # should use digest_sns_topic here
                }
            }
        }
        topic = self.publisher.formatted_sns_topic_arn(test_config)
        assert topic == 'arn:aws:sns:us-east-1:123456789012:foobar'

    def test_format_digest_no_stats(self):
        """StatsPublisher - Format Digest, No Stats"""
        digest = self.publisher._format_digest([])
        assert digest == 'No currently staged rules to report on'

    def test_format_digest(self):
        """StatsPublisher - Format Digest"""
        expected_digest = '''\u25E6 test_rule_1
	- Staged At:					2000-01-01 01:01:01 UTC
	- Staged Until:					2000-01-03 01:01:01 UTC
	- Remaining Stage Time:		1d 0h 0m
	- Alert Count:					2
	- Alert Info:					n/a

\u25E6 test_rule_0
	- Staged At:					2000-01-01 01:01:01 UTC
	- Staged Until:					2000-01-03 01:01:01 UTC
	- Remaining Stage Time:		1d 0h 0m
	- Alert Count:					1
	- Alert Info:					n/a'''
        stats = list(self._get_fake_stats())
        digest = self.publisher._format_digest(stats)
        assert digest == expected_digest

    @patch('streamalert.rule_promotion.publisher.StatsPublisher._publish_message')
    def test_query_alerts_none(self, publish_mock):
        """StatsPublisher - Query Alerts, No Alerts for Stat"""
        stats = list(self._get_fake_stats(count=1))
        stats[0].alert_count = 0
        with patch.object(self.publisher, '_athena_client', new_callable=PropertyMock) as mock:
            self.publisher.publish(stats)
            assert stats[0].execution_id is None
            mock.run_async_query.assert_not_called()
            publish_mock.assert_called_with(stats)

    def test_query_alerts_bad_reponse(self):
        """StatsPublisher - Query Alerts, Bad Response"""
        stat = list(self._get_fake_stats(count=1))[0]
        with patch.object(self.publisher, '_athena_client', new_callable=PropertyMock) as mock:
            mock.run_async_query.side_effect = athena.AthenaQueryExecutionError()
            pytest.raises(athena.AthenaQueryExecutionError, self.publisher._query_alerts, stat)

    def test_query_alerts(self):
        """StatsPublisher - Query Alerts"""
        stat = list(self._get_fake_stats(count=1))[0]
        execution_id = '678cc350-d4e1-4296-86d5-9351b7f92ed4'
        with patch.object(self.publisher, '_athena_client', new_callable=PropertyMock) as mock:
            mock.run_async_query.return_value = {'QueryExecutionId': execution_id}
            assert self.publisher._query_alerts(stat) == execution_id

    @patch('streamalert.rule_promotion.publisher.boto3')
    def test_publish_message(self, boto_mock):
        """StatsPublisher - Publish Message"""
        self.publisher._publish_message(list(self._get_fake_stats(count=1)))

        args = {
            'Message': '''\u25E6 test_rule_0
	- Staged At:					2000-01-01 01:01:01 UTC
	- Staged Until:					2000-01-03 01:01:01 UTC
	- Remaining Stage Time:		1d 0h 0m
	- Alert Count:					1
	- Alert Info:					n/a''',
            'Subject': 'Alert statistics for 1 staged rule(s) [2000-01-01 01:01:01 UTC]'
        }
        boto_mock.resource.return_value.Topic.return_value.publish.assert_called_with(**args)

    @patch('streamalert.rule_promotion.publisher.StatsPublisher._publish_message')
    @patch('streamalert.rule_promotion.publisher.StatsPublisher._query_alerts')
    def test_publish(self, query_mock, publish_mock):
        """StatsPublisher - Publish, False"""
        query_mock.return_value = 'fake-id'
        stats = list(self._get_fake_stats(count=1))
        self.publisher.publish(stats)
        publish_mock.assert_called_with(stats)

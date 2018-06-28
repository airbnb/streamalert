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
from datetime import datetime, timedelta
import json
import os

import boto3
from mock import Mock, patch, PropertyMock
from moto import mock_ssm
from nose.tools import assert_equal

from stream_alert.rule_promotion.publisher import StatsPublisher
from stream_alert.rule_promotion.statistic import StagingStatistic


class TestStatsPublisher(object):
    """Tests for rule_promotion/publisher.py:StatsPublisher"""
    # pylint: disable=protected-access

    @patch.object(StatsPublisher, '_load_state', Mock())
    def setup(self):
        """StatsPublisher - Setup"""
        # pylint: disable=attribute-defined-outside-init
        self.publisher = StatsPublisher(
            topic_arn='arn:aws:sns:us-east-1:123456789012:test-topic',
            athena_client=None,
            current_time=datetime(year=2000, month=1, day=1, hour=1, minute=1, second=1)
        )

        self.publisher._state = {
            'sent_daily_digest': False,
            'send_digest_hour_utc': 12
        }

    @staticmethod
    def _put_ssm_param(sent=False):
        """Helper function to put fake ssm param for StatsPublisher"""
        param = json.dumps({
            'sent_daily_digest': sent,
            'send_digest_hour_utc': 9
        })
        boto3.client('ssm').put_parameter(
            Name=StatsPublisher.SSM_STATE_NAME,
            Value=param,
            Type='String'
        )

    @staticmethod
    def _get_fake_stats(count=2):
        """Helper function to return fake StagingStatistics"""
        stage_time = datetime(year=2000, month=1, day=1, hour=1, minute=1, second=1)
        for i in range(count):
            stat = StagingStatistic(
                staged_at=stage_time,
                staged_until=stage_time + timedelta(days=2),
                current_time=stage_time + timedelta(days=1),
                rule='test_rule_{}'.format(i)
            )
            stat.alert_count = i + 1
            yield stat

    def test_format_digest_no_stats(self):
        """StatsPublisher - Format Digest, No Stats"""
        digest = self.publisher._format_digest([])
        assert_equal(digest, 'No currently staged rules to report on')

    def test_format_digest(self):
        """StatsPublisher - Format Digest"""
        expected_digest = u'''\u25E6 test_rule_1
	- Staged At:                        2000-01-01 01:01:01 UTC
	- Staged Until:                     2000-01-03 01:01:01 UTC
	- Remaining Stage Time:             1d 0h 0m
	- Alert Count:                      2
	- Alert Info:                       n/a

\u25E6 test_rule_0
	- Staged At:                        2000-01-01 01:01:01 UTC
	- Staged Until:                     2000-01-03 01:01:01 UTC
	- Remaining Stage Time:             1d 0h 0m
	- Alert Count:                      1
	- Alert Info:                       n/a'''.encode('utf-8')
        stats = list(self._get_fake_stats())
        digest = self.publisher._format_digest(stats)
        assert_equal(digest, expected_digest)

    @mock_ssm
    def test_load_state(self):
        """StatsPublisher - Load State"""
        expected_param = {
            'sent_daily_digest': False,
            'send_digest_hour_utc': 9
        }
        with patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'}):
            self._put_ssm_param()
            assert_equal(self.publisher._load_state(), expected_param)

    @patch('stream_alert.rule_promotion.publisher.StatsPublisher.SSM_CLIENT')
    def test_write_state(self, ssm_mock):
        """StatsPublisher - Write State"""
        # Change the current time hour so the publisher assumes the digest was sent
        self.publisher._current_time = self.publisher._current_time.replace(hour=9)
        self.publisher._state['send_digest_hour_utc'] = 9

        # sent_daily_digest should be True now since the hour in the day == 9
        args = {
            'Name': 'staging_stats_publisher_state',
            'Value': json.dumps({
                'sent_daily_digest': True,
                'send_digest_hour_utc': 9
            }),
            'Overwrite': True
        }
        self.publisher._write_state()
        ssm_mock.put_parameter.assert_called_with(**args)

    def test_query_alerts_none(self):
        """StatsPublisher - Query Alerts, No Alerts for Stat"""
        stat = list(self._get_fake_stats(count=1))[0]
        stat.alert_count = 0
        with patch.object(self.publisher, '_athena_client', new_callable=PropertyMock) as mock:
            assert_equal(self.publisher._query_alerts(stat), None)
            mock.run_async_query.assert_not_called()

    @patch('logging.Logger.error')
    def test_query_alerts_bad_reponse(self, log_mock):
        """StatsPublisher - Query Alerts, Bad Response"""
        stat = list(self._get_fake_stats(count=1))[0]
        with patch.object(self.publisher, '_athena_client', new_callable=PropertyMock) as mock:
            mock.run_async_query.return_value = None
            assert_equal(self.publisher._query_alerts(stat), None)
            mock.run_async_query.assert_called_once()
            log_mock.assert_called_with(
                'Failed to query alert info for rule: \'%s\'', 'test_rule_0')

    def test_query_alerts(self):
        """StatsPublisher - Query Alerts"""
        stat = list(self._get_fake_stats(count=1))[0]
        execution_id = '678cc350-d4e1-4296-86d5-9351b7f92ed4'
        with patch.object(self.publisher, '_athena_client', new_callable=PropertyMock) as mock:
            mock.run_async_query.return_value = {'QueryExecutionId': execution_id}
            assert_equal(self.publisher._query_alerts(stat), execution_id)

    @patch('stream_alert.rule_promotion.publisher.boto3')
    def test_publish_message(self, boto_mock):
        """StatsPublisher - Publish Message"""
        self.publisher._publish_message(list(self._get_fake_stats(count=1)))

        args = {
            'Message': u'''\u25E6 test_rule_0
	- Staged At:                        2000-01-01 01:01:01 UTC
	- Staged Until:                     2000-01-03 01:01:01 UTC
	- Remaining Stage Time:             1d 0h 0m
	- Alert Count:                      1
	- Alert Info:                       n/a'''.encode('utf-8'),
            'Subject': 'Alert statistics for 1 staged rule(s) [2000-01-01 01:01:01 UTC]'
        }
        boto_mock.resource.return_value.Topic.return_value.publish.assert_called_with(**args)

    def test_should_send_digest(self):
        """StatsPublisher - Should Send Digest Property, True"""
        # the 'current hour' is also 1, so set digest sending hour to 1
        self.publisher._state['send_digest_hour_utc'] = 1
        assert_equal(self.publisher._should_send_digest, True)

    def test_should_not_send_digest(self):
        """StatsPublisher - Should Send Digest Property, False"""
        assert_equal(self.publisher._should_send_digest, False)

    @patch('logging.Logger.debug')
    @patch('stream_alert.rule_promotion.publisher.StatsPublisher._write_state')
    def test_do_not_publish(self, write_mock, log_mock):
        """StatsPublisher - Publish, False"""
        self.publisher.publish(None)
        log_mock.assert_called_with('Daily digest will not be sent')
        write_mock.assert_called_once()

    @patch('stream_alert.rule_promotion.publisher.StatsPublisher._publish_message')
    @patch('stream_alert.rule_promotion.publisher.StatsPublisher._query_alerts')
    @patch('stream_alert.rule_promotion.publisher.StatsPublisher._write_state', Mock())
    def test_publish(self, query_mock, publish_mock):
        """StatsPublisher - Publish, False"""
        query_mock.return_value = 'fake-id'
        stats = list(self._get_fake_stats(count=1))
        self.publisher._state['send_digest_hour_utc'] = 1
        self.publisher.publish(stats)
        publish_mock.assert_called_with(stats)

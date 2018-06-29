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
import os

from mock import patch
from nose.tools import assert_equal

from stream_alert.rule_promotion.statistic import StagingStatistic


class TestStagingStatistic(object):
    """Tests for rule_promotion/statistic.py:StagingStatistic"""
    # pylint: disable=protected-access

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """StagingStatistic - Setup"""
        # pylint: disable=attribute-defined-outside-init
        stage_time = datetime(year=2000, month=1, day=1, hour=1, minute=1, second=1)
        self.statistic = StagingStatistic(
            staged_at=stage_time,
            staged_until=stage_time + timedelta(days=2),
            current_time=stage_time + timedelta(days=1),
            rule='test_rule'
        )

    def test_construct_compound_count_query(self):
        """StagingStatistic - Construct Compound Count Query"""
        query = StagingStatistic.construct_compound_count_query([self.statistic, self.statistic])
        expected_query = ("SELECT 'test_rule' AS rule_name, count(*) AS count "
                          "FROM alerts WHERE dt >= '2000-01-01-01' AND "
                          "rule_name = 'test_rule' UNION ALL SELECT 'test_rule' "
                          "AS rule_name, count(*) AS count FROM alerts WHERE "
                          "dt >= '2000-01-01-01' AND rule_name = 'test_rule'")

        assert_equal(query, expected_query)

    def test_sql_count_statement(self):
        """StagingStatistic - SQL Count Statement"""
        expected_sql = ("SELECT 'test_rule' AS rule_name, count(*) AS count FROM alerts "
                        "WHERE dt >= '2000-01-01-01' AND rule_name = 'test_rule'")
        assert_equal(self.statistic.sql_count_statement, expected_sql)

    def test_sql_info_statement(self):
        """StagingStatistic - SQL Info Statement"""
        expected_sql = ("SELECT id, rule_name, created, cluster, log_source, source_entity, "
                        "record FROM alerts WHERE dt >= '2000-01-01-01' AND "
                        "rule_name = 'test_rule' ORDER BY created DESC")
        assert_equal(self.statistic.sql_info_statement, expected_sql)

    def test_stringer_past(self):
        """StagingStatistic - Stringer, Past Staging"""
        self.statistic.alert_count = 200
        self.statistic._current_time += timedelta(days=2, hours=10)
        expected_string = u'''\u25E6 test_rule
	- Staged At:					2000-01-01 01:01:01 UTC
	- Staged Until:					2000-01-03 01:01:01 UTC
	- Time Past Staging:			1d 10h 0m
	- Alert Count:					200
	- Alert Info:					n/a'''.encode('utf-8')

        assert_equal(str(self.statistic), expected_string)

    def test_stringer_remaining(self):
        """StagingStatistic - Stringer, Staging Remaining"""
        self.statistic.alert_count = 100
        self.statistic.execution_id = '678cc350-d4e1-4296-86d5-9351b7f92ed4'
        expected_string = u'''\u25E6 test_rule
	- Staged At:					2000-01-01 01:01:01 UTC
	- Staged Until:					2000-01-03 01:01:01 UTC
	- Remaining Stage Time:		1d 0h 0m
	- Alert Count:					100
	- Alert Info:					https://console.aws.amazon.com/athena/\
home#query/history/678cc350-d4e1-4296-86d5-9351b7f92ed4'''.encode('utf-8')

        assert_equal(str(self.statistic), expected_string)

    def test_comp(self):
        """StagingStatistic - Comparison"""
        self.statistic.alert_count = 200
        second_stat = StagingStatistic(
            staged_at='fake_staged_at_time',
            staged_until='fake_staged_until_time',
            current_time='fake_current_time',
            rule='test_rule'
        )
        second_stat.alert_count = 100

        assert_equal(self.statistic > second_stat, True)

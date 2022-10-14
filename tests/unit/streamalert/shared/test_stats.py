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
# pylint: disable=no-self-use,attribute-defined-outside-init
from collections import namedtuple
from unittest.mock import Mock, patch

from streamalert.shared import stats


class TestRuleStats:
    """TestRuleStats class"""

    def setup(self):
        stats.RuleStatisticTracker.STATS.clear()
        self._fake_rule = namedtuple('Rule', ['name', 'process'])('test_rule', lambda r: False)
        self._tracker = stats.RuleStatisticTracker(True)

    def test_time_rule(self):
        """RuleStatisticTracker - Time Rule"""
        self._tracker.run_rule(self._fake_rule, {})
        assert len(self._tracker.STATS) == 1
        assert self._tracker.STATS['test_rule'].calls == 1

    @patch('time.time')
    def test_tracker_disabled(self, time_mock):
        """RuleStatisticTracker - Disabled"""
        tracker = stats.RuleStatisticTracker(False)
        tracker.run_rule(self._fake_rule, {})
        time_mock.assert_not_called()

    def test_rule_stats_add(self):
        """RuleStatistic - Addition"""
        stat = stats.RuleStatistic(10.0)
        stat += stats.RuleStatistic(12.5)

        assert stat.calls == 1
        assert stat.tracked_time == 22.5

    def test_rule_stats_compare(self):
        """RuleStatistic - Comparison"""
        stat_01 = stats.RuleStatistic(10.0)
        stat_02 = stats.RuleStatistic(12.0)

        assert stat_01 < stat_02
        assert (stat_01 > stat_02) == False

    def test_rule_stats_string(self):
        """RuleStatistic - Stringer"""
        stat = stats.RuleStatistic(10.0)
        stat.calls = 1
        assert str(stat) == '   10.00000000 ms       1 calls     10.00000000 avg'

    @patch('logging.Logger.error')
    def test_get_rule_stats_empty(self, log_mock):
        """RuleStatisticTracker - Statistics Info, None"""
        stats.RuleStatisticTracker.statistics_info()
        log_mock.assert_called_with('No rule statistics to return')

    @patch('time.time', Mock(side_effect=[0.01, 0.02]))
    def test_get_rule_stats(self):
        """RuleStatisticTracker - Statistics Info"""
        self._tracker.run_rule(self._fake_rule, {})
        result = stats.RuleStatisticTracker.statistics_info()
        assert (
            result ==
            'Rule statistics:\n\ntest_rule       10.00000000 ms       1 calls     10.00000000 avg')

    def test_get_rule_stats_retain(self,):
        """RuleStatisticTracker - Statistics Info, Retain Results"""
        self._tracker.run_rule(self._fake_rule, {})
        assert len(self._tracker.STATS) == 1
        new_tracker = stats.RuleStatisticTracker(True, False)
        assert len(new_tracker.STATS) == 1

    def test_get_rule_stats_reset(self,):
        """RuleStatisticTracker - Statistics Info, Reset"""
        self._tracker.run_rule(self._fake_rule, {})
        assert len(self._tracker.STATS) == 1
        new_tracker = stats.RuleStatisticTracker(True, True)
        assert len(new_tracker.STATS) == 0

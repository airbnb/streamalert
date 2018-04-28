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
# pylint: disable=no-self-use
from collections import namedtuple

from mock import Mock, patch
from nose.tools import assert_equal

from stream_alert.shared import stats


class TestRuleStats(object):
    """TestTimeRule class"""
    def setup(self):
        stats.RULE_STATS.clear()

    def teardown(self):
        stats.RULE_STATS.clear()

    @staticmethod
    def _timed_func_helper():
        @stats.time_rule
        def test_func(_):
            pass

        fake = namedtuple('Rule', ['name'])('test_rule')

        test_func(fake)

    def test_time_rule(self):
        """Stats - Time Rule, Decorator"""
        self._timed_func_helper()
        assert_equal(len(stats.RULE_STATS), 1)
        assert_equal(stats.RULE_STATS['test_rule'].calls, 1)

    def test_rule_stats_add(self):
        """Stats - Rule Statistics, Add"""
        stat = stats.RuleStatistic(10.0)
        stat += stats.RuleStatistic(12.5)

        assert_equal(stat.calls, 1)
        assert_equal(stat.tracked_time, 22.5)

    def test_rule_stats_compare(self):
        """Stats - Rule Statistics, Compare"""
        stat_01 = stats.RuleStatistic(10.0)
        stat_02 = stats.RuleStatistic(12.0)

        assert_equal(stat_01 < stat_02, True)
        assert_equal(stat_01 > stat_02, False)


    def test_rule_stats_string(self):
        """Stats - Rule Statistics, To String"""
        stat = stats.RuleStatistic(10.0)
        stat.calls = 1

        assert_equal(str(stat), '   10.00000000 ms       1 calls     10.00000000 avg')

    @patch('logging.Logger.error')
    def test_print_rule_stats_empty(self, log_mock):
        """Stats - Print Rule Stats, None"""
        stats.print_rule_stats()
        log_mock.assert_called_with('No rule statistics to print')

    @patch('time.time', Mock(side_effect=[0.01, 0.02]))
    @patch('logging.Logger.info')
    def test_print_rule_stats(self, log_mock):
        """Stats - Print Rule Stats"""
        self._timed_func_helper()
        stats.print_rule_stats()
        log_mock.assert_called_with(
            'Rule statistics:\n%s',
            'test_rule       10.00000000 ms       1 calls     10.00000000 avg'
        )

    def test_print_rule_stats_reset(self,):
        """Stats - Print Rule Stats, Reset"""
        self._timed_func_helper()
        stats.print_rule_stats(True)
        assert_equal(len(stats.RULE_STATS), 0)

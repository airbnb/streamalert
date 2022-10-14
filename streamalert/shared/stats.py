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
import time
from collections import defaultdict

from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


class RuleStatisticTracker:

    STATS = defaultdict(lambda: RuleStatistic(0.0))

    def __init__(self, enabled, clear_cache=False):
        self.enabled = enabled
        if clear_cache:
            self.__class__.STATS.clear()

    def run_rule(self, rule, record):
        """Timing function for timing a rule function's duration

        Note: this function's timing aspect is a no-op if the RuleStatisticTracker
            is disabled, and instead the rule just runs without timing

        Args:
            rule (rule.Rule): The rule being ran
            record (dict): The record being processed

        Returns:
            bool: Result of rule processing
        """
        if not self.enabled:
            return rule.process(record)

        time_start = time.time()
        result = rule.process(record)
        time_end = time.time()

        self.__class__.STATS[rule.name] += RuleStatistic((time_end - time_start) * 1000)

        return result

    @classmethod
    def statistics_info(cls):
        """Return human-readable information on rule stats"""
        if not cls.STATS:
            LOGGER.error('No rule statistics to return')
            return

        max_rule_name_len = max(len(rule) for rule in cls.STATS)

        stat_lines = [
            '{rule: <{pad}}{stat}'.format(rule=rule, pad=max_rule_name_len + 4, stat=stat)
            for rule, stat in sorted(iter(cls.STATS.items()), key=lambda k_v: (k_v[1], k_v[0]))
        ]

        return 'Rule statistics:\n\n{}'.format('\n'.join(stat_lines))


class RuleStatistic:
    """Simple class for tracking rule times and call count"""
    def __init__(self, proc_time):
        self.calls = 0
        self.tracked_time = proc_time

    def __add__(self, other):
        self.calls += 1
        self.tracked_time += other.tracked_time
        return self

    def __lt__(self, other):
        return self.tracked_time < other.tracked_time

    def __str__(self):
        return '{:14.8f} ms  {:6d} calls  {:14.8f} avg'.format(self.tracked_time, self.calls,
                                                               self.tracked_time / self.calls)


def time_me(func):
    """Timing decorator for wrapping a function"""
    def timed(*args, **kw):
        """Wrapping function"""
        time_start = time.time()
        result = func(*args, **kw)
        time_end = time.time()

        message = '(module) {} (method) {} (time): {:>.4f}ms'.format(func.__module__, func.__name__,
                                                                     (time_end - time_start) * 1000)

        LOGGER.debug(message)

        return result

    return timed

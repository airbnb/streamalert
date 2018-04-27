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
from collections import defaultdict

import time

from stream_alert.shared import LOGGER


RULE_STATS = defaultdict(lambda: RuleStatistic(0.0))

class RuleStatistic(object):
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
        return '{:14.8f} ms  {:6d} calls  {:14.8f} avg'.format(
            self.tracked_time,
            self.calls,
            self.tracked_time/self.calls
        )


def time_me(func):
    """Timing decorator for wrapping a function"""

    def timed(*args, **kw):
        """Wrapping function"""
        time_start = time.time()
        result = func(*args, **kw)
        time_end = time.time()

        message = '(module) {} (method) {} (time): {:>.4f}ms'.format(
            func.__module__, func.__name__, (time_end - time_start) * 1000
        )

        LOGGER.debug(message)

        return result

    return timed


def time_rule(rule_func):
    """Timing decorator for specifically timing a rule function"""
    def timed(self, *args, **kwargs):
        """Wrapping function"""
        time_start = time.time()
        result = rule_func(self, *args, **kwargs)
        time_end = time.time()

        RULE_STATS[self.name] += RuleStatistic((time_end - time_start) * 1000)

        return result

    return timed


def print_rule_stats(reset=False):
    """Print some additional rule stats

    Args:
        reset (bool): Optional flag to reset the tracking statistics after printing
    """
    if not RULE_STATS:
        LOGGER.error('No rule statistics to print')
        return

    max_rule_name_len = max([len(rule) for rule in RULE_STATS.keys()])

    stat_lines = []
    for rule, stat in sorted(RULE_STATS.iteritems(), key=lambda (k, v): (v, k)):
        stat_lines.append(
            '{rule: <{pad}}{stat}'.format(rule=rule, pad=max_rule_name_len+4, stat=stat))

    LOGGER.info('Rule statistics:\n%s', '\n'.join(stat_lines))

    # Clear the dictionary that is storing statistics
    # This allows for resetting when cumulative stats are not wanted
    if reset:
        RULE_STATS.clear()

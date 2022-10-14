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


class StagingStatistic:
    """Store information on generated alerts."""

    _ALERT_COUNT_UNKOWN = -1

    _COUNT_QUERY_TEMPLATE = (
        "SELECT rule_name, count(*) AS count FROM alerts WHERE {where_clause} GROUP BY rule_name")

    _COUNT_QUERY_WHERE_FRAGMENT = "(dt >= '{date}-{hour:02}' AND rule_name = '{rule_name}')"

    _INFO_QUERY_TEMPLATE = ("SELECT id, rule_name, created, cluster, log_source, source_entity, "
                            "record FROM alerts WHERE dt >= '{date}-{hour:02}' AND "
                            "rule_name = '{rule_name}' ORDER BY created DESC")

    _QUERY_EXECUTION_LINK_TEMPLATE = ('https://console.aws.amazon.com/athena/home'
                                      '#query/history/{execution_id}')

    def __init__(self, staged_at, staged_until, current_time, rule):
        self._rule_name = rule
        self._current_time = current_time
        self._staged_at = staged_at
        self.staged_until = staged_until
        self.alert_count = self._ALERT_COUNT_UNKOWN
        self.execution_id = None

    def __bool__(self):
        return self.alert_count not in {0, self._ALERT_COUNT_UNKOWN}

    def __lt__(self, other):
        """Statistic should be ordered by their alert count."""
        return self.alert_count < other.alert_count

    @classmethod
    def construct_compound_count_query(cls, stats):
        """Create a SQL query to get the alert counts for staged rules

        Args:
            stats (list[StagingStatistic])

        Returns:
            list: SQL statement for counting alerts created by staged rules
        """
        where_clause = ' OR '.join(stat.sql_where_fragment for stat in stats)
        return cls._COUNT_QUERY_TEMPLATE.format(where_clause=where_clause)

    @property
    def sql_where_fragment(self):
        return self._COUNT_QUERY_WHERE_FRAGMENT.format(date=self._staged_at.date().isoformat(),
                                                       hour=self._staged_at.hour,
                                                       rule_name=self._rule_name)

    @property
    def sql_info_statement(self):
        """Athena info statement for this rule to get comprehensive alert info."""
        return self._INFO_QUERY_TEMPLATE.format(date=self._staged_at.date().isoformat(),
                                                hour=self._staged_at.hour,
                                                rule_name=self._rule_name)

    @property
    def rule_name(self):
        """Read only property for rule name"""
        return self._rule_name

    def __str__(self):
        """Return a human-readable respresentation of the stat's data"""
        info = self.__dict__.copy()

        info.update({
            'staged_at_label': 'Staged At',
            'staged_until_label': 'Staged Until',
            'alert_count_label': 'Alert Count',
            'alert_info_label': 'Alert Info',
            'pad': 34
        })

        info['staged_time_label'] = ('Remaining Stage Time:'
                                     if self.staged_until > self._current_time else
                                     'Time Past Staging:\t')

        staged_diff = abs(self._current_time - self.staged_until)
        info[
            'staged_delta'] = f'{staged_diff.days}d {staged_diff.seconds // 3600}h {staged_diff.seconds // 60 % 60}m'

        info['info_link'] = (self._QUERY_EXECUTION_LINK_TEMPLATE.format(
            execution_id=self.execution_id) if self.execution_id else 'n/a')

        info['alert_count'] = 'unknown' if info['alert_count'] == -1 else info['alert_count']

        # \u25E6 is unicode for a bullet
        return ('\u25E6 {_rule_name}\n'
                '\t- {staged_at_label}:\t\t\t\t\t{_staged_at} UTC\n'
                '\t- {staged_until_label}:\t\t\t\t\t{staged_until} UTC\n'
                '\t- {staged_time_label}\t\t{staged_delta}\n'
                '\t- {alert_count_label}:\t\t\t\t\t{alert_count}\n'
                '\t- {alert_info_label}:\t\t\t\t\t{info_link}').format(**info)

"""
Matchers extract common logic into helpers that can be referenced in
multiple rules.  For example, if we write an osquery rule that
is specific for the `prod` environment, we can define a matcher
and add it to our rules' `match` keyword argument:

@rule('root_logins', logs=['osquery:differential'], matchers=['prod'],
      outputs=['pagerduty:sample-integration'])

You can also supply multiple matchers for many common scenarios:

@rule('root_logins', logs=['osquery:differential'],
      matchers=['prod', 'pci'], outputs=['pagerduty:sample-integration'])
"""
# from helpers.base import in_set, last_hour
from stream_alert.rule_processor.rules_engine import StreamRules

matcher = StreamRules.matcher()

@matcher
def guard_duty(record):
    return record['detail-type'] == 'GuardDuty Finding'

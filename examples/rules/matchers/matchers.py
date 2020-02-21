"""
Matchers extract common logic into helpers that can be referenced in
multiple rules.  For example, if we write an osquery rule that
is specific for the `prod` environment, we can define a matcher
and add it to our rules' `matchers` keyword argument:

from rules.matchers import matchers

@rule('root_logins', logs=['osquery:differential'], matchers=[matchers.prod],
      outputs=['pagerduty:sample-integration'])

You can also supply multiple matchers for many common scenarios:

@rule('root_logins', logs=['osquery:differential'],
      matchers=[matchers.prod, matchers.pci], outputs=['pagerduty:sample-integration'])
"""


def guard_duty(record):
    return record['detail-type'] == 'GuardDuty Finding'

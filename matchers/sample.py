"""
Matchers extract common logic into helpers that can be referenced in
multiple rules.  For example, if we write an osquery rule that
is specific for the `prod` environment, we can define a matcher
and add it to our rules' `match` keyword argument:

    @rule('root_logins', data_source=['osquery'], matchers=['prod'],
          sink=['csirt-pagerduty'])

You can also supply multiple matchers for many common scenarios:

    @rule('root_logins', data_source=['osquery'],
          matchers=['prod', 'itx_corp'], sink=['csirt-pagerduty'])
"""
from helpers.base import in_set, last_hour
from stream_alert.rule_processor.rules_engine import StreamRules

matcher = StreamRules.matcher()

# Basic matcher for checking environments
# based on a key within a record
@matcher
def production_env(rec):
    return rec['env'] == 'production'

@matcher
def json_test_matcher(rec):
    return rec['name'] == 'name-1'

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
from stream_alert.rule_helpers import in_set, last_hour
from stream_alert.rules_engine import StreamRules

matcher = StreamRules.matcher

# basic matcher for checking environments
@matcher('production_env')
def production_env(rec):
    env = rec['env']
    return env == 'production'


# matcher rlayout
@matcher('matcher_name')
def matcher_name(rec):
    """Description"""
    return True

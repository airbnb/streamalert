from stream_alert.rules_engine import StreamRules
from stream_alert.rule_helpers import in_set, last_hour

rule = StreamRules.rule

# osquery invalid user
@rule('invalid_user',
      logs=['osquery'],
      matchers=[],
      outputs=['pagerduty'])
def invalid_user_rule(rec):
    """Catch unauthorized user logins"""
    auth_users = {'alice', 'bob'}
    query = rec['name']
    user = rec['columns']['user']

    return (
        query == 'logged_in_users' and
        user not in auth_users
    )


# invalid subnet rule
from netaddr import IPAddress, IPNetwork

@rule('invalid_subnet',
      logs=['osquery'],
      matchers=['logged_in_users'],
      outputs=['pagerduty'])
def invalid_subnet_rule(rec):
    """Catch logins from unauthorized subnets"""
    valid_cidr = IPNetwork('10.2.0.0/24')
    ip = IPAddress(rec['columns']['host'])

    return ip not in valid_cidr


# rule layout
@rule('rule', 
      logs=[],
      matchers=[],
      outputs=[])
def rule_func(rec):
    """Description"""
    return True

from helpers.base import in_set, last_hour
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

# # Note: This is the rule layout
# @rule(logs=['foo'],
#       matchers=['foo'],
#       outputs=['foo'])
# def rule(rec):
#     """Description"""
#     pass

# osquery invalid user
@rule(logs=['osquery'],
      matchers=[],
      outputs=['s3'],
      req_subkeys={'columns': ['user']})
def invalid_user(rec):
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

@rule(logs=['osquery'],
      matchers=[],
      outputs=['slack'],
      req_subkeys={'columns': ['host']})
def invalid_subnet(rec):
    """Catch logins from unauthorized subnets"""
    valid_cidr = IPNetwork('10.2.0.0/24')
    ip = IPAddress(rec['columns']['host'])

    return (
        rec['name'] == 'logged_in_users' and
        ip not in valid_cidr
    )


@rule(logs=['json_log'],
      matchers=[],
      outputs=['s3'])
def sample_json_rule(rec):
    return rec['host'] == 'test-host-1'


@rule(logs=['syslog_log'],
      matchers=[],
      outputs=['pagerduty'])
def sample_syslog_rule(rec):
    return rec['application'] == 'sudo'


@rule(logs=['csv_log'],
      matchers=[],
      outputs=['s3'])
def sample_csv_rule(rec):
    return rec['host'] == 'test-host-2'


@rule(logs=['kv_log'],
      matchers=[],
      outputs=['s3'])
def sample_kv_rule(rec):
    return (
        rec['msg'] == 'fatal' and
        rec['uid'] == 100
    )


@rule(logs=['kv_log'],
      matchers=[],
      outputs=['s3'])
def sample_kv_rule_last_hour(rec):
    return (
        rec['type'] == 'start' and
        rec['uid'] == 0 and
        last_hour(rec['time'])
    )

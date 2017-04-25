from helpers.base import in_set, last_hour
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule
disable = StreamRules.disable()

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
      outputs=['aws-s3:sample.bucket'],
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
      outputs=['slack:sample_channel'],
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
      matchers=['json_test_matcher'],
      outputs=['aws-s3'])
def sample_json_rule(rec):
    return rec['host'] == 'test-host-1'

@disable
@rule(logs=['syslog_log'],
      matchers=[],
      outputs=['pagerduty:sample_integration'])
def sample_syslog_rule(rec):
    return rec['application'] == 'sudo'


@rule(logs=['csv_log'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def sample_csv_rule(rec):
    return rec['host'] == 'test-host-2'


@rule(logs=['kv_log'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def sample_kv_rule(rec):
    return (
        rec['msg'] == 'fatal' and
        rec['uid'] == 100
    )


@rule(logs=['kv_log'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def sample_kv_rule_last_hour(rec):
    return (
        rec['type'] == 'start' and
        rec['uid'] == 0 and
        last_hour(rec['time'])
    )


@rule(logs=['cloudtrail:v1.05'],
      matchers=[],
      outputs=['slack:sample_channel'])
def sample_cloudtrail_rule(rec):
    """Non Lambda/Kinesis service AssumedRole"""
    whitelist_services = {
        'lambda.amazonaws.com',
        'kinesis.amazonaws.com'
    }

    return (
        rec['eventName'] == 'AssumeRole' and
        rec['awsRegion'] == 'us-east-1' and
        not in_set(rec['userIdentity']['invokedBy'], whitelist_services)
    )


@rule(logs=['cloudwatch:ec2_event'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def sample_cloudwatch_events_rule(rec):
    """Any activity on EC2"""
    return rec['source'] == 'aws.ec2'


@rule(logs=['cloudwatch:cloudtrail'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def sample_cloudwatch_cloudtrail_rule(rec):
    """IAM Key Decrypt operation"""
    return rec['detail']['eventName'] == 'Decrypt'


@rule(logs=['cloudwatch:flow_logs'],
      matchers=[],
      outputs=['slack:sample_channel'])
def sample_cloudwatch_flog_log_rule(rec):
    """Successful SSH connection"""
    return (
        rec['destport'] == 22 and
        rec['action'] == 'ACCEPT'
    )

@rule(logs=['carbonblack:event01'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def carbonblack_event_01(rec):
    """CarbonBlack event01 Matched MD5"""
    return rec['md5'] == '0BF4D085933DCF869D7FFFFFFFFF1111'


@rule(logs=['carbonblack:event02'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def carbonblack_event_02(rec):
    """CarbonBlack event02 Matched MD5"""
    return rec['md5'] == '0BF4D085933DCF869D7FFFFFFFFF4444'


@rule(logs=['carbonblack:nested_matching'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def sample_json_nested_matching(rec):
    """Nested JSON Matched Computer Name"""
    return (rec['computer_name'] == 'ml134134134foobar' and
            rec['nest_test']['key01'] == 'value01'
    )

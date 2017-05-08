from rules.helpers.base import in_set, last_hour
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

@rule(logs=['carbonblack:ingress.event.filemod'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def carbonblack_ingress_event_filemod(rec):
    """CarbonBlack Ingress Event Filemod Matched MD5"""
    return rec['md5'] == '7A2870C2A8283B3630BF7670D0362B94'


@rule(logs=['carbonblack:ingress.event.regmod'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def carbonblack_ingress_event_regmod(rec):
    """CarbonBlack Ingress Event Regmod Matched MD5"""
    return rec['md5'] == '0E7196981EDE614F1F54FFF2C3843ADF'


@rule(logs=['carbonblack:binaryinfo.host.observed'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def carbonblack_binaryinfo_host_observed(rec):
    """CarbonBlack BinaryInfo Host Observed Watchlist Match"""
    return (rec['hostname'] == 'FS-HQ' and
            rec['md5'] == '9E4B0E7472B4CEBA9E17F440B8CB0AB8'
    )


@rule(logs=['carbonblack:binaryinfo.host.observed_alternate'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def carbonblack_binaryinfo_host_observed_alternate(rec):
    """CarbonBlack BinaryInfo Host Observed Watchlist Match"""
    return (rec['hostname'] == 'FS-HQ' and
            rec['md5'] == '9E4B0E7472B4CEBA9E17F440B8CB0CCC'
    )

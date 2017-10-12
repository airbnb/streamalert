"""Alert on AWS Security Groups that allow ingress from anywhere."""
from helpers.base import select_key
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['cloudwatch:events'],
      matchers=[],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'],
      req_subkeys={'detail': ['eventName', 'requestParameters']})
def cloudtrail_security_group_ingress_anywhere(rec):
    """
    author:         @mimeframe, @ryandeivert
    description:    Alert on AWS Security Groups that allow ingress from anywhere.
                    This rule accounts for both IPv4 and IPv6.
    reference:      http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/
                    using-network-security.html#creating-security-group
    """
    if rec['detail']['eventName'] != 'AuthorizeSecurityGroupIngress':
        return False

    ipv4_cidrs = select_key(rec['detail']['requestParameters'], 'cidrIp')
    ipv6_cidrs = select_key(rec['detail']['requestParameters'], 'cidrIpv6')

    if '0.0.0.0/0' in ipv4_cidrs:
        return True

    if '::/0' in ipv6_cidrs:
        return True

    return False

"""Alert on AWS Security Groups that allow ingress from anywhere."""
from rules.helpers.base import get_keys
from streamalert.shared.rule import rule


@rule(logs=['cloudwatch:events'], req_subkeys={'detail': ['eventName', 'requestParameters']})
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

    ipv4_cidrs = get_keys(rec['detail']['requestParameters'], 'cidrIp')
    ipv6_cidrs = get_keys(rec['detail']['requestParameters'], 'cidrIpv6')

    return True if '0.0.0.0/0' in ipv4_cidrs else '::/0' in ipv6_cidrs

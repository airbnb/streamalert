"""Alert on AWS Network ACLs that allow ingress from anywhere."""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['cloudwatch:events'],
      matchers=[],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'],
      req_subkeys={'detail': ['eventName', 'requestParameters']})
def cloudtrail_network_acl_ingress_anywhere(rec):
    """
    author:         @mimeframe
    description:    Alert on AWS Network ACLs that allow ingress from anywhere.
    reference_1:    http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_ACLs.html
    reference_2:    http://docs.aws.amazon.com/AWSEC2/
                    latest/APIReference/API_CreateNetworkAclEntry.html
    """
    if rec['detail']['eventName'] != 'CreateNetworkAclEntry':
        return False

    req_params = rec['detail']['requestParameters']

    return (
        req_params['cidrBlock'] == '0.0.0.0/0' and
        req_params['ruleAction'] == 'allow' and
        req_params['egress'] is False
    )

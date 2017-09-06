"""Alert on dangerous S3 object ACLs."""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule


@rule(logs=['cloudtrail:events'],
      matchers=[],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'],
      req_subkeys={'requestParameters': ['accessControlList']})
def cloudtrail_put_object_acl(rec):
    """
    author:         airbnb_csirt
    description:    Identifies a change to an S3 object ACL that grants access to AllUsers
                    (anyone on the internet) or AuthenticatedUsers (any user with an AWS account)
    reference:      http://docs.aws.amazon.com/
                        AmazonS3/latest/dev/acl-overview.html#specifying-grantee
    playbook:       (a) identify who set the ACL by looking at `userIdentity`
                    (b) ping that individual to verify the object should be accessible to the world
                    (c) if not, remove the object ACL and investigate access logs
    """
    if rec['eventName'] != 'PutObject':
        return False

    insecure_acl_list = {
        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
        'http://acs.amazonaws.com/groups/global/AllUsers'
    }

    acl_entries = {value for value in rec['requestParameters']['accessControlList'].values()}

    return any(blacklist in acl for acl in acl_entries for blacklist in insecure_acl_list)

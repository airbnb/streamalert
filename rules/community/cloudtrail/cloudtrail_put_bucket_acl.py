"""Alert on dangerous S3 bucket ACLs."""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule


@rule(logs=['cloudwatch:events'],
      matchers=[],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'],
      req_subkeys={'detail': ['requestParameters', 'eventName']})
def cloudtrail_put_bucket_acl(rec):
    """
    author:       airbnb_csirt
    description:  Identifies a change to an S3 bucket ACL that grants access to AllUsers
                  (anyone on the internet) or AuthenticatedUsers (any user on any AWS account)
    reference:    http://docs.aws.amazon.com/
                      AmazonS3/latest/dev/acl-overview.html#specifying-grantee
    playbook:     (a) identify who made the change by looking at `userIdentity`
                  (b) ping that individual to verify the bucket should be accessible to the world
                  (c) if not, remove the bucket ACL and investigate access logs
    """
    if rec['detail']['eventName'] != 'PutBucketAcl':
        return False
    elif rec['detail']['requestParameters'] is None:
        # `requestParameters` can be defined with a value of null
        return False

    insecure_acl_list = {
        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
        'http://acs.amazonaws.com/groups/global/AllUsers'
    }

    req_params = rec['detail']['requestParameters']
    access_control_policy = req_params.get('AccessControlPolicy')
    if not access_control_policy:
        return False

    grants = access_control_policy['AccessControlList']['Grant']
    insecure_buckets = []

    for grant in grants:
        grantee = grant.get('Grantee', [])
        if 'URI' in grantee:
            insecure_buckets.append(grantee['URI'] in insecure_acl_list)

    return any(insecure_buckets)

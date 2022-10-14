"""Alert on dangerous S3 bucket ACLs."""
from streamalert.shared.rule import rule

_DENIED_ACLS = {
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
    'http://acs.amazonaws.com/groups/global/AllUsers'
}


@rule(logs=['cloudwatch:events'], req_subkeys={'detail': ['requestParameters', 'eventName']})
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
        # check the event type early to avoid unnecessary performance impact
        return False
    if rec['detail']['requestParameters'] is None:
        # requestParameters can be defined with a value of null
        return False

    req_params = rec['detail']['requestParameters']
    access_control_policy = req_params.get('AccessControlPolicy')
    if not access_control_policy:
        return False

    grants = access_control_policy['AccessControlList']['Grant']
    bad_bucket_permissions = []

    for grant in grants:
        grantee = grant.get('Grantee', [])
        if 'URI' in grantee:
            bad_bucket_permissions.append(grantee['URI'] in _DENIED_ACLS)

    return any(bad_bucket_permissions)

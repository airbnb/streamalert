"""Identifies new S3 object ACLs that grant access to the public."""
from rules.helpers.base import data_has_value_from_substring_list
from streamalert.shared.rule import rule

_PUBLIC_ACLS = {
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
    'http://acs.amazonaws.com/groups/global/AllUsers'
}

# s3 buckets that are expected to have public objects
_PUBLIC_BUCKETS = {'example-bucket-to-ignore'}


@rule(logs=['cloudwatch:events'], req_subkeys={'detail': ['requestParameters']})
def cloudtrail_put_object_acl_public(rec):
    """
    author:         @mimeframe
    description:    Identifies a change to an S3 object ACL that grants access
                    to AllUsers (anyone on the internet) or AuthenticatedUsers
                    (any user with an AWS account).
    reference:      http://amzn.to/2yfRxzp
    playbook:       (a) Verify if the object should be publicly accessible
                    (b) If not, modify the object ACL
    """
    request_params = rec['detail']['requestParameters']
    return (
        rec['detail']['eventName'] == 'PutObjectAcl' and
        # note: substring is used because it can exist as:
        # "http://acs.amazonaws.com/groups/global/AllUsers" or
        # "uri=http://acs.amazonaws.com/groups/global/AllUsers"
        data_has_value_from_substring_list(request_params, _PUBLIC_ACLS)
        and request_params.get('bucketName') not in _PUBLIC_BUCKETS)

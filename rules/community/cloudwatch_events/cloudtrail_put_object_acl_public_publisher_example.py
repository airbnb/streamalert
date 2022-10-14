"""Identifies new S3 object ACLs that grant access to the public."""
from publishers.community.generic import add_record, populate_fields
from publishers.community.pagerduty.pagerduty_layout import (PrettyPrintArrays,
                                                             ShortenTitle,
                                                             as_custom_details)
from publishers.community.slack.slack_layout import (AttachFullRecord,
                                                     AttachRuleInfo, Summary)
from rules.helpers.base import data_has_value_from_substring_list
from streamalert.shared.rule import rule

_PUBLIC_ACLS = {
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
    'http://acs.amazonaws.com/groups/global/AllUsers'
}


@rule(logs=['cloudwatch:events'],
      req_subkeys={'detail': ['eventName', 'requestParameters', 'sourceIPAddress']},
      outputs=['slack:sample-channel', 'pagerduty:sample-integration'],
      publishers={
          'slack': [Summary, AttachRuleInfo, AttachFullRecord],
          'pagerduty':
          [add_record, populate_fields, PrettyPrintArrays, ShortenTitle, as_custom_details],
      },
      context={
          'populate_fields': [
              'userName',
              'sourceIPAddress',
              'eventTime',
              'eventName',
              'eventSource',
              'bucketName',
          ]
      })
def cloudtrail_put_object_acl_public_publisher_example(rec, _):
    """
    description:    Identifies a change to an S3 object ACL that grants access
                    to AllUsers (anyone on the internet) or AuthenticatedUsers
                    (any user with an AWS account).

    note: This is purely for example purposes in testing, and is not meant to be used as-is
    """
    if rec['detail']['sourceIPAddress'] != '1.2.3.4':
        return False  # Hack to avoid triggering for other tests events

    request_params = rec['detail']['requestParameters']
    return (
        rec['detail']['eventName'] == 'PutObjectAcl' and
        # note: substring is used because it can exist as:
        # "http://acs.amazonaws.com/groups/global/AllUsers" or
        # "uri=http://acs.amazonaws.com/groups/global/AllUsers"
        data_has_value_from_substring_list(request_params, _PUBLIC_ACLS))

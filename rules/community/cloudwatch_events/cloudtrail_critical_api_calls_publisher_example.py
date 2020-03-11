"""Alert on destructive AWS API calls."""
from publishers.community.generic import add_record, populate_fields
from publishers.community.pagerduty.pagerduty_layout import (
    ShortenTitle, as_custom_details,
    PrettyPrintArrays,
)
from publishers.community.slack.slack_layout import Summary, AttachRuleInfo, AttachFullRecord
from streamalert.shared.rule import rule

_CRITICAL_EVENTS = {
    # VPC Flow Logs (~netflow)
    'DeleteFlowLogs',
    # Critical, large resources
    'DeleteSubnet',
    'DeleteVpc',
    'DeleteDBCluster',
    'DeleteCluster',
    # CloudTrail
    'DeleteTrail',
    'UpdateTrail',
    'StopLogging',
    # AWS Config
    'DeleteDeliveryChannel',
    'StopConfigurationRecorder',
    # CloudWatch
    'DeleteRule',
    'DisableRule',
    # GuardDuty
    'DeleteDetector',
    # S3 Public Access Block
    'DeleteAccountPublicAccessBlock',
    # EBS default encryption
    'DisableEbsEncryptionByDefault',
}


@rule(
    logs=['cloudtrail:events'],
    outputs=['slack:sample-channel', 'pagerduty:sample-integration'],
    publishers={
        'slack': [Summary, AttachRuleInfo, AttachFullRecord],
        'pagerduty': [
            add_record,
            populate_fields,
            PrettyPrintArrays,
            ShortenTitle,
            as_custom_details
        ],
    },
    context={
        'populate_fields': ['eventName', 'eventSource']
    }
)
def cloudtrail_critical_api_calls_publisher_example(rec, _):
    """
    description:  Alert on AWS API calls in us-west-1 region that stop or delete
                  security/infrastructure logs.
                  Additionally, alert on AWS API calls that delete critical resources
                  (VPCs, Subnets, DB's, ...)

    note: This is purely for example purposes in testing, and is not meant to be used as-is
    """
    return rec['eventName'] in _CRITICAL_EVENTS and rec['awsRegion'] == 'us-west-1'

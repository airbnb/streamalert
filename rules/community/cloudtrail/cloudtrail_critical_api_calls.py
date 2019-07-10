"""Alert on destructive AWS API calls."""
from stream_alert.shared.rule import rule

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


@rule(logs=['cloudtrail:events'])
def cloudtrail_critical_api_calls(rec):
    """
    author:           airbnb_csirt
    description:      Alert on AWS API calls that stop or delete security/infrastructure logs.
                      Additionally, alert on AWS API calls that delete critical resources
                      (VPCs, Subnets, DB's, ...)
    reference:        https://medium.com/@robwitoff/
                          proactive-cloud-security-w-aws-organizations-d58695bcae16#.tx2e6iju0
    playbook:         (a) identify the AWS account in the log
                      (b) identify what resource(s) are impacted by the API call
                      (c) determine if the intent is valid, malicious or accidental
    """
    if rec['eventName'] in _CRITICAL_EVENTS:
        return True

    if rec['eventName'] == 'UpdateDetector':
        # Check if GuardDuty is being disabled, where enable is set to False
        if not rec.get('requestParameters', {}).get('enable', True):
            return True

    if rec['eventName'] == 'PutBucketPublicAccessBlock':
        # Check if any of the types of public access for a bucket have been disabled
        config = rec.get('requestParameters', {}).get(
            'PublicAccessBlockConfiguration', {}
        )
        if (
                not config.get('RestrictPublicBuckets', False)
                and not config.get('BlockPublicPolicy', False)
                and not config.get('BlockPublicPolicy', False)
                and not config.get('BlockPublicPolicy', False)
        ):
            return True

    # PutAccountPublicAccessBlock does not indicate if the account is
    # enabling or disabling this feature so to reduce FPs,
    # for now this is not being detected.
    # This issue was reported to aws-security@amazon.com by spiper
    # on 2019.07.09

    return False

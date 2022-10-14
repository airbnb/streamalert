"""Alert on destructive AWS API calls."""
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
    'PutEventSelectors',
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

PUBLIC_ACCESS_BLOCK_CONFIG_ACTIONS = {
    'RestrictPublicBuckets',
    'BlockPublicPolicy',
    'BlockPublicAcls',
    'IgnorePublicAcls',
}

AWS_ORG_EVENTS = {
    'AttachPolicy',
    'CreateOrganizationUnit',
    'CreatePolicy',
    'DeletePolicy',
    'DeleteOrganizationUnit',
    'DetachPolicy',
    'DisableAWSServiceAccess',
    'DisablePolicyType',
    'EnableAllFeatures',
    'EnableAWSServiceAccess',
    'EnablePolicyType',
    'LeaveOrganization',
    'MoveAccount',
    'RemoveAccountFromOrganization',
    'UpdatePolicy',
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

    if rec['eventName'] == 'UpdateDetector' and not rec.get('requestParameters', {}).get('enable', True):
        return True

    if rec['eventName'] in {'PutBucketPublicAccessBlock', 'PutAccountPublicAccessBlock'}:
        # These calls set the policy for what to block for a bucket.
        # We need to get the configuration and see if any
        # of the items are set to False.
        config = rec.get('requestParameters', {}).get('PublicAccessBlockConfiguration', {})
        for action in PUBLIC_ACCESS_BLOCK_CONFIG_ACTIONS:
            if config.get(action, True) is False:
                return True

    # Detect important Organizations calls
    return rec['eventSource'] == 'organizations.amazonaws.com' and rec['eventName'] in AWS_ORG_EVENTS

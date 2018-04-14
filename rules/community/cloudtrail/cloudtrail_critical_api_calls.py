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
    'DisableRule'
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
    return rec['eventName'] in _CRITICAL_EVENTS

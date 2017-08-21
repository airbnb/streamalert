"""Alert on destructive AWS API calls."""
from helpers.base import in_set
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule
disable = StreamRules.disable()


@rule(logs=['cloudtrail:events'],
      matchers=[],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'])
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
    critical_events = {
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

    return in_set(rec['eventName'], critical_events)

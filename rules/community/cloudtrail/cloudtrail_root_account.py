from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule
disable = StreamRules.disable()


@rule(logs=['cloudwatch:events'],
      matchers=[],
      outputs=['aws-s3:sample_bucket', 'aws-lambda:sample_lambda',
               'pagerduty:sample_integration', 'phantom:sample_integration',
               'slack:sample_channel'],
      req_subkeys={'detail': ['userIdentity', 'eventType']})
def cloudtrail_root_account(rec):
    """
    author:           airbnb_csirt
    description:      Root AWS credentials are being used;
                      This is against best practice and may be an attacker
    reference_1:      https://aws.amazon.com/premiumsupport/knowledge-center/cloudtrail-root-action-logs/
    reference_2:      http://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
    playbook:         (a) identify who is using the Root account
                      (b) ping the individual to determine if intentional and/or legitimate
    """

    # see reference_1 for details
    return (
        rec['detail']['userIdentity']['type'] == 'Root' and
        rec['detail']['userIdentity'].get('invokedBy') is None and
        rec['detail']['eventType']!= 'AwsServiceEvent'
    )

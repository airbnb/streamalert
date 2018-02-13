"""Alert on GuardDuty"""
from helpers.base import in_set
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule
disable = StreamRules.disable()


@rule(logs=['cloudwatch:events'],
      matchers=[],
      outputs=['slack:sample-channel'])
def guardduty(rec):
    """
    author:         spiper
    description:    Alert on GuardDuty events
    playbook:       (a) identify the AWS account in the log
                    (b) identify what resource(s) are impacted
                    (c) contact the point-of-contact for the account
    testing:        From the GuardDuty AWS page (https://console.aws.amazon.com/guardduty/home)
                    click the button to "Generate Sample Findings"
    """

    if rec['detail-type'] == 'GuardDuty Finding':
        return True
    return False

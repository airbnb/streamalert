"""Alert on GuardDuty"""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule
disable = StreamRules.disable()


@rule(logs=['cloudwatch:events'],
      matchers=['guard_duty'],
      outputs=['slack:sample-channel'])
def guard_duty_all(*_):
    """
    author:         spiper
    description:    Alert on GuardDuty events
    playbook:       (a) identify the AWS account in the log
                    (b) identify what resource(s) are impacted
                    (c) contact the point-of-contact for the account
    testing:        From the GuardDuty AWS page (https://console.aws.amazon.com/guardduty/home)
                    click the button to "Generate Sample Findings"
    """

    return True

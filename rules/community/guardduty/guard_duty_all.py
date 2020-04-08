"""Alert on GuardDuty"""
from matchers.default import AwsGuardDutyMatcher
from streamalert.shared.rule import rule


@rule(logs=['cloudwatch:events'], matchers=[AwsGuardDutyMatcher.guard_duty])
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

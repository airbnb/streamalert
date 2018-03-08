"""Alert on Trusted Advisor"""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule
disable = StreamRules.disable()


@rule(logs=['cloudwatch:events'],
      matchers=['trusted_advisor'],
      outputs=['slack:sample-channel'])
def trusted_advisor(rec):
    """
    author:         spiper
    description:    Alert on Trusted Advisor events.
                    Note that these will only go to CloudWatch events if you
                    have a Business support contract or better for the account.
    playbook:       Depends on the alert. Some of these are misconfigurations,
                    some are warnings that you are approaching limits, and some
                    and critical alerts that need to be responded to (such as
                    access keys being pushed to github).
    testing:        Create an S3 bucket with a random name and no contents,
                    and make it publicly read-able.
    """
    detail = rec['detail']
    check_name = detail.get('check-name', '')

    # Ignore checks that tell us things are OK
    if detail.get('status', '') == 'OK':
        return False

    # The check are somewhat documented at: https://aws.amazon.com/premiumsupport/ta-iam/

    # Known checks to alert on
    if check_name == 'Security Groups - Specific Ports Unrestricted':
        return True
    if check_name == 'MFA on Root Account':
        return True
    if check_name == 'IAM Password Policy':
        return True
    if check_name == 'AWS CloudTrail Logging':
        return True
    if check_name == 'Exposed Access Keys':
        return True
    if check_name == 'Amazon Route 53 MX Resource Record Sets and Sender Policy Framework':
        return True

    # Ignore everything else
    return False

"""Alert on AWS Config"""
from matchers.default import AwsConfigMatcher
from streamalert.shared.rule import rule

# Populate this list to alert on specific Config Rules, otherwise all rules will be in-scope
# Also consider the use of Lookup-Tables
RULES_TO_ALERT_ON = []


@rule(logs=["cloudtrail:events"], matchers=[AwsConfigMatcher.is_config_compliance])
def config_compliance(record):
    """
    author:         jack (jack1902)
    description:    Alert on AWS Config Complaince Change events of NON_COMPLIANT
    testing:        From the Config page (https://console.aws.amazon.com/config/home)
                    ensure recording is turned on. And you have a basic rule you can
                    trigger as compliant or non-compliant.
    """

    non_compliance_present = any(evaluation["complianceType"] == "NON_COMPLIANT"
                                 for evaluation in record["requestParameters"]["evaluations"])

    if RULES_TO_ALERT_ON:
        # Alert on specific rule names. Useful when some Config Rules are just TOO noisy.
        rule_name = record["additionalEventData"]["configRuleName"]
        return rule_name in RULES_TO_ALERT_ON and non_compliance_present
    else:
        # Alert on ALL config rules regardless of their name
        return non_compliance_present


@rule(logs=["cloudtrail:events"], matchers=[AwsConfigMatcher.is_auto_remediation])
def config_auto_remediation(_):
    """
    author:         jack (jack1902)
    description:    Alert on AWS Config Auto Remediation
    testing:        From the Config page (https://console.aws.amazon.com/config/home)
                    ensure recording is turned on. And you have a basic rule you can
                    trigger as compliant or non-compliant. Then trigger the remediation
                    either manually or have it done automatically.
    """
    return True

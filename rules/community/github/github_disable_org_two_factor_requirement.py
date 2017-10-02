"""Github two-factor authentication requirement was disabled."""
from helpers.base import ghe_json_message
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['ghe:general'],
      matchers=['github_audit'],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'])
def github_disable_org_two_factor_requirement(rec):
    """
    author:       @mimeframe
    description:  Two-factor authentication requirement was disabled.
    reference:    https://help.github.com/
                  articles/requiring-two-factor-authentication-in-your-organization/
    """
    message_rec = ghe_json_message(rec)
    if not message_rec:
        return False

    return message_rec.get('action') == 'org.disable_two_factor_requirement'

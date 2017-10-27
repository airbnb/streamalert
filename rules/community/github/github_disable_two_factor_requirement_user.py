"""Github two-factor authentication requirement was disabled for a user."""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['ghe:general'],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'])
def github_disable_two_factor_requirement_user(rec):
    """
    author:       @mimeframe
    description:  Two-factor authentication requirement was disabled for a user.
    repro_steps:  (a) Visit /settings/two_factor_authentication/configure
    reference:    https://help.github.com/enterprise/2.11/admin/articles/audited-actions/
    """
    return rec['action'] == 'two_factor_authentication.disabled'

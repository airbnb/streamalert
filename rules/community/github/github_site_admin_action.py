"""A Github site admin tool/action was used."""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['ghe:general'],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'])
def github_site_admin_action(rec):
    """
    author:       @mimeframe
    description:  A Github site admin tool/action was used.
                  Example: 'staff.fake_login'
                   "A site admin signed into GitHub Enterprise as another user.""
    reference:    https://help.github.com/enterprise/2.11/admin/articles/audited-actions/
    """
    return rec['action'].startswith('staff.')

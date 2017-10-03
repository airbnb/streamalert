"""A Github Enterprise user account was promoted to a site admin."""
from helpers.base import ghe_json_message
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['ghe:general'],
      matchers=['github_audit'],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'])
def github_user_promotion_to_site_admin(rec):
    """
    author:       @fusionrace, @mimeframe
    description:  Alert when a Github Enterprise user account is promoted to a
                  Site Administrator (privileged account)
    reference:    https://help.github.com/enterprise/2.11/admin/guides/
                  user-management/promoting-or-demoting-a-site-administrator/
    """
    message_rec = ghe_json_message(rec)
    if not message_rec:
        return False

    return message_rec.get('action') == 'user.promote'

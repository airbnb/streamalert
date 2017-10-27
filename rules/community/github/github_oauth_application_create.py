"""An OAuth application was registered within Github."""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['ghe:general'],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'])
def github_oauth_application_create(rec):
    """
    author:       @mimeframe
    description:  An OAuth application was registered within Github.
    reference:    https://developer.github.com
                  /apps/building-integrations/setting-up-and-registering-oauth-apps/
    """
    return rec['action'] == 'oauth_application.create'

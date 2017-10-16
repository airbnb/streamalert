"""Alert when a DUO bypass code is created that is non-expiring."""
import json
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['duo:administrator'],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'])
def duo_bypass_code_create_non_expiring(rec):
    """
    author:       @mimeframe
    description:  Alert when a DUO bypass code is created that is non-expiring.
    reference:    https://duo.com/docs/administration-users#generating-a-bypass-code
    """
    return (
        rec['action'] == 'bypass_create' and
        json.loads(rec['description']).get('valid_secs') is None
    )

"""Alert when a DUO bypass code is artisanly crafted and not auto-generated."""
import json
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['duo:administrator'],
      outputs=['aws-s3:sample-bucket',
               'pagerduty:sample-integration',
               'slack:sample-channel'])
def duo_bypass_code_create_non_auto_generated(rec):
    """
    author:       @mimeframe
    description:  Alert when a DUO bypass code is artisanly crafted and not auto-generated.
    reference:    https://duo.com/docs/administration-users#generating-a-bypass-code
    """
    return (
        rec['action'] == 'bypass_create' and
        json.loads(rec['description']).get('auto_generated') is False
    )

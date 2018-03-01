"""Alert on webhook being called."""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule

@rule(logs=['webhook'],
      matchers=[],
      outputs=['slack:alerts'])
def webhook(rec):
    return True

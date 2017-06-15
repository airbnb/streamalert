from stream_alert.rule_processor.rules_engine import StreamRules
rule = StreamRules.rule
disable = StreamRules.disable()

@rule(logs=['bro:dns'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def bro_dns(rec):
    """
    reference:    https://www.bro.org/sphinx/scripts/base/protocols/dns/main.bro.html#type-DNS::Info
    """
    return False

from stream_alert.rule_processor.rules_engine import StreamRules
rule = StreamRules.rule
disable = StreamRules.disable()

@rule(logs=['bro:conn'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def bro_conn(rec):
    """
    reference:    https://www.bro.org/sphinx/scripts/base/protocols/conn/main.bro.html#type-Conn::Info
    """
    return False

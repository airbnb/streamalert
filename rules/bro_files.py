from stream_alert.rule_processor.rules_engine import StreamRules
rule = StreamRules.rule
disable = StreamRules.disable()

@rule(logs=['bro:files'],
      matchers=[],
      outputs=['aws-s3:sample.bucket'])
def bro_files(rec):
    """
    reference:    https://www.bro.org/sphinx/scripts/base/frameworks/files/main.bro.html#type-Files::Info
    """
    return False

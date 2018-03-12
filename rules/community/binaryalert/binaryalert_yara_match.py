"""Alert on BinaryAlert YARA matches"""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule


@rule(logs=['binaryalert'],
      outputs=['aws-sns:sample-topic'])
def binaryalert_yara_match(rec):
    """
    author:       Austin Byers (Airbnb CSIRT)
    description:  BinaryAlert found a binary matching a YARA rule
    reference:    https://binaryalert.io
    """
    return rec['NumMatchedRules'] > 0

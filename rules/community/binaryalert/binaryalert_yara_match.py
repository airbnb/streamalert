"""Alert on BinaryAlert YARA matches"""
from streamalert.shared.rule import rule


@rule(logs=['binaryalert'])
def binaryalert_yara_match(rec):
    """
    author:       Austin Byers (Airbnb CSIRT)
    description:  BinaryAlert found a binary matching a YARA rule
    reference:    https://binaryalert.io
    """
    return rec['NumMatchedRules'] > 0

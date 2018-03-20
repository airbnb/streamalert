"""Alert on any Duo auth logs marked as fraud."""
from stream_alert.rule_processor.rules_engine import StreamRules

rule = StreamRules.rule


@rule(logs=['duo:authentication'])
def duo_fraud(rec):
    """
    author:       airbnb_csirt
    description:  Alert on any Duo authentication logs marked as fraud.
    reference:    https://duo.com/docs/adminapi#authentication-logs
    playbook:     N/A
    """
    return rec['result'] == 'FRAUD'

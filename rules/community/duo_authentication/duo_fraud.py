"""Alert on any Duo auth logs marked as fraud."""
from streamalert.shared.rule import rule


@rule(logs=['duo:authentication'])
def duo_fraud(rec):
    """
    author:       airbnb_csirt
    description:  Alert on any Duo authentication logs marked as fraud.
    reference:    https://duo.com/docs/adminapi#authentication-logs
    playbook:     N/A
    """
    return rec['result'] == 'FRAUD'

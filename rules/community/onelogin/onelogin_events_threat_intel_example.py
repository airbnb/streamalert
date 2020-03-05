"""Alert on the OneLogin event that a user has assumed the role of someone else."""
from streamalert.shared.rule import rule
from streamalert.rules_engine.threat_intel import ThreatIntel


@rule(logs=['onelogin:events'])
def onelogin_events_threat_intel_example(rec):
    """
    description: Alert on OneLogin activity from a malicious IP address using threat intel
    note: This is purely for example purposes in testing, and is not meant to be used as-is
    """
    # The 'local' fixture file at rules/community/onelogin/test_fixtures/threat_intel/example.json
    # mocks out the threat intel values used by this rule

    # In this case, the rec['ipaddr'] value is a "known" malicious IP, so this will alert
    return ThreatIntel.IOC_KEY in rec and 'ip' in rec[ThreatIntel.IOC_KEY]

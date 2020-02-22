"""Alert on PacketBeat events"""
from streamalert.shared.rule import rule


@rule(logs=['packetbeat:dns'])
def packetbeat_example_com_lookup(rec):
    """
    author:       gavin (gavinelder)
    description:  Alert on DNS lookup for Blacklisted domain
    testing:      (a) Review traffic logs for machine in question.
    """
    return rec['dns']['question']['name'].endswith('.evil.com.')

"""Alert on PacketBeat events"""
from streamalert.shared.rule import rule


@rule(logs=['packetbeat:dns'])
def packetbeat_dns_lookup(rec):
    """
    author:       gavin (gavinelder)
    description:  Alert on DNS lookup for Blacklisted domain
    testing:      (a) Review traffic logs for machine in question.
    reference:    https://www.elastic.co/guide/en/beats/packetbeat/master/packetbeat-overview.html
    """
    return rec['dns']['question']['name'].endswith('.evil.com.')

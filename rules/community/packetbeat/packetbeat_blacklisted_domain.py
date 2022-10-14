"""Alert on PacketBeat events"""

from streamalert.shared.rule import rule

DNS_BLACKLIST = ['evil.com.']


@rule(logs=['packetbeat:dns'])
def packetbeat_blacklisted_domain(rec):
    """
    author:       gavin (gavinelder)
    description:  Lookup for BlackListed DNS (CnC).
    testing:      (a) Review traffic logs for machine in question.
    reference:    https://www.elastic.co/guide/en/beats/packetbeat/master/packetbeat-overview.html
    """
    return rec['dns']['question']['name'] in DNS_BLACKLIST

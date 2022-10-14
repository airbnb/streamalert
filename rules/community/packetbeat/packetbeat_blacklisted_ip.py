"""Alert on PacketBeat events"""
import ipaddress

from streamalert.shared.rule import rule

IP_BLACKLIST = [
    '222.173.190.239',
]


@rule(logs=['packetbeat:flow'])
def packetbeat_blacklisted_ip(rec):
    """
    author:       gavin (gavinelder)
    description:  Network connection to blacklisted IP.
    testing:      (a) Review traffic logs for machine in question.
    reference:    https://www.elastic.co/guide/en/beats/packetbeat/master/packetbeat-overview.html
    """
    return ipaddress.IPv4Address(rec['source']['ip']) and rec['dest']['ip'] in IP_BLACKLIST

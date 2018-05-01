"""
shared helpers
"""

import logging
from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError

logging.basicConfig()
LOGGER = logging.getLogger('StreamAlert')

def valid_ip(ip_address):
    """Verify that a ip_address string is valid

    Args:
        ip_address (string): address to be tested

    Returns:
        True if the ip_address is valid, otherwise False
    """
    # Early return if ip address is '::1'
    if ip_address == '::1':
        return False

    try:
        IPAddress(ip_address)
    except: # pylint: disable=bare-except
        return False
    return True


def in_network(ip_address, cidrs):
    """Check that an ip_address is within a set of CIDRs

    Args:
        ip_address (str or netaddr.IPAddress): IP address to check
        cidrs (set): String CIDRs

    Returns:
        Boolean representing if the given IP is within any CIDRs
    """
    if not valid_ip(ip_address):
        return False

    for cidr in cidrs:
        try:
            network = IPNetwork(cidr)
        except AddrFormatError:
            LOGGER.error('Invalid IP Network: %s', cidr)
            continue
        if ip_address in network:
            return True
    return False

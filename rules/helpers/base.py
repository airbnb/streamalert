'''
Copyright 2017-present, Airbnb Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import logging
import time

from fnmatch import fnmatch
from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError

logging.basicConfig()
LOGGER = logging.getLogger('StreamAlert')

def in_set(data, whitelist):
    """Checks if data exists in any elements of a whitelist.

    Args:
        data: element in list
        whitelist: list/set to search in

    Returns:
        True/False
    """
    return any(fnmatch(data, x) for x in whitelist)

def last_hour(unixtime, hours=1):
    """Check if a given epochtime is within the last hour.

    Args:
        unixtime: epoch time

    Returns:
        True/False
    """
    seconds = hours * 3600
    # sometimes bash histories do not contain the `time` column
    if unixtime:
        return int(time.time()) - int(unixtime) <= seconds
    else:
        return False

def valid_ip(ip_address):
    """Verify that a ip_address string is valid

    Args:
        ip_address: A string to cast into an IPAddress class

    Returns:
        IPAddress object or None if an invalid address
    """
    try:
        valid_ip = IPAddress(ip_address)
    except AddrFormatError:
        return False
    return True

def in_network(ip_address, cidrs):
    """Check that an ip_address is within a set of CIDRs

    Args:
        ip_address: netaddr IPAddress object
        cidrs: a set of string CIDRs

    Returns:
        Boolean representing if the given IP is within any CIDRs
    """
    for cidr in cidrs:
        try:
            network = IPNetwork(cidr)
        except AddrFormatError:
            LOGGER.error('Invalid IP Network: %s', cidr)
            continue
        if ip_address in network:
            return True
    return False

"""
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
"""
from fnmatch import fnmatch
import logging
import time

from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError

from stream_alert.rule_processor.threat_intel import StreamThreatIntel

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
    """Check if a given epochtime is within the last hour(s).

    Args:
        unixtime: epoch time
        hours (int): number of hours

    Returns:
        True/False
    """
    seconds = hours * 3600
    # sometimes bash histories do not contain the `time` column
    return int(time.time()) - int(unixtime) <= seconds if unixtime else False


def valid_ip(ip_address):
    """Verify that a ip_address string is valid

    Args:
        ip_address (string): address to be tested

    Returns:
        True if the ip_address is valid, otherwise False
    """
    try:
        IPAddress(ip_address)
    except AddrFormatError:
        return False
    return True


def in_network(ip_address, cidrs):
    """Check that an ip_address is within a set of CIDRs

    Args:
        ip_address (netaddr.IPAddress): IP address to check
        cidrs (set): String CIDRs

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

def fetch_values_by_datatype(rec, datatype):
    """Fetch values of normalized_type.

    Args:
        rec (dict): parsed payload of any log
        datatype (str): normalized type user interested

    Returns:
        (list) The values of normalized types
    """
    results = []
    if not datatype in rec['normalized_types']:
        return results

    for original_keys in rec['normalized_types'][datatype]:
        result = rec
        if isinstance(original_keys, list):
            for original_key in original_keys:
                result = result[original_key]
        results.append(result)

    return results

def is_ioc(rec):
    """Detect is any data in a record matching to known IOC"""
    intel = StreamThreatIntel.get_intelligence()
    datatypes_ioc_mapping = StreamThreatIntel.get_config()

    if not (datatypes_ioc_mapping and rec.get('normalized_types')):
        return False

    for datatype in rec['normalized_types']:
        if datatype not in datatypes_ioc_mapping:
            continue
        results = fetch_values_by_datatype(rec, datatype)
        for result in results:
            if (intel.get(datatypes_ioc_mapping[datatype])
                    and result in intel[datatypes_ioc_mapping[datatype]]):
                if 'streamalert:ioc' in rec:
                    rec['streamalert:ioc'].append({
                        'type': datatypes_ioc_mapping[datatype],
                        'value': result
                    })
                else:
                    rec.update({
                        'streamalert:ioc': {
                            'type': datatypes_ioc_mapping[datatype],
                            'value': result
                        }
                    })
    if 'streamalert:ioc' in rec:
        return True

    return False

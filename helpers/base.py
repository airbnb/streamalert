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
import json
import logging
import re
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
    if not rec.get('normalized_types'):
        return results

    if not datatype in rec['normalized_types']:
        return results

    for original_keys in rec['normalized_types'][datatype]:
        result = rec
        if isinstance(original_keys, list):
            for original_key in original_keys:
                result = result[original_key]
        results.append(result)

    return results

def is_ioc(rec, lowercase_ioc=True):
    """Detect is any data in a record matching to known IOC

    Args:
        rec (dict): The parsed payload of any log
        lowercase_ioc (bool): Indicate if IOCs in IOC files are in lowercase or
            uppercase. If true, it will convert data found in the record to
            lowercase.
            This flag is implemented to achieve case-insensitive comparison
            between IOCs and related data in the record.

    Returns:
        (bool): Returns True if data matching to any IOCs, otherwise returns
            False.
    """
    intel = StreamThreatIntel.get_intelligence()
    datatypes_ioc_mapping = StreamThreatIntel.get_config()

    if not (datatypes_ioc_mapping and rec.get('normalized_types')):
        return False

    for datatype in rec['normalized_types']:
        if datatype not in datatypes_ioc_mapping:
            continue
        results = fetch_values_by_datatype(rec, datatype)
        for result in results:
            if isinstance(result, str):
                result = result.lower() if lowercase_ioc else result.upper()
            if (intel.get(datatypes_ioc_mapping[datatype])
                    and result in intel[datatypes_ioc_mapping[datatype]]):
                if StreamThreatIntel.IOC_KEY in rec:
                    rec[StreamThreatIntel.IOC_KEY].append({
                        'type': datatypes_ioc_mapping[datatype],
                        'value': result
                    })
                else:
                    rec.update({
                        StreamThreatIntel.IOC_KEY: [{
                            'type': datatypes_ioc_mapping[datatype],
                            'value': result
                        }]
                    })
    if StreamThreatIntel.IOC_KEY in rec:
        return True

    return False

def ghe_json_message(rec):
    """Given a GHE log, extract the JSON payload from the message field

    Args:
        rec [string]: The StreamPayload parsed record

    Returns:
        [dict]: Parsed JSON GHE message field
        [NoneType]: If no valid JSON object is found in the message field
    """
    json_pattern = re.compile(r'(?P<json_message>\{.*\})')
    match = re.search(json_pattern, rec['message'])

    if not match:
        return

    json_message = match.group('json_message')
    try:
        message_rec = json.loads(json_message)
    except ValueError:
        return

    return message_rec

def select_key(data, search_key, results=None):
    """Recursively search for a given key and return all values
    Args:
        data (dict, list)
        search_key (string)
        results (array)

    Returns:
        (list) all values
    """
    if results is None:
        results = []
    # Check for lists - this will handle lists of lists, etc
    if isinstance(data, list):
        for item in data:
            select_key(item, search_key, results)
    # Only dictionaries can have keys, so return here if this is not one
    if not isinstance(data, dict):
        return
    # Iterate over all of the key/values
    for key, val in data.iteritems():
        # Handle nested dictionaries
        if isinstance(val, dict):
            select_key(val, search_key, results)
        # Handle lists within a dictonary - the safety check at the top will handle nesting
        elif isinstance(val, list):
            select_key(val, search_key, results)
        elif key == search_key:
            # Finally, if this key is in the dictionary, extract the value for
            # it and append to the results list that is passed by reference
            results.append(val)
    return results

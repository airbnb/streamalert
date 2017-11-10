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

from stream_alert.shared import NORMALIZATION_KEY
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
    if not rec.get(NORMALIZATION_KEY):
        return results

    if not datatype in rec[NORMALIZATION_KEY]:
        return results

    for original_keys in rec[NORMALIZATION_KEY][datatype]:
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

    if not (datatypes_ioc_mapping and rec.get(NORMALIZATION_KEY)):
        return False

    for datatype in rec[NORMALIZATION_KEY]:
        if datatype not in datatypes_ioc_mapping:
            continue
        results = fetch_values_by_datatype(rec, datatype)
        for result in results:
            if isinstance(result, str):
                result = result.lower() if lowercase_ioc else result.upper()
            if (intel.get(datatypes_ioc_mapping[datatype])
                    and result in intel[datatypes_ioc_mapping[datatype]]):
                insert_ioc_info(rec, datatypes_ioc_mapping[datatype], result)
    if StreamThreatIntel.IOC_KEY in rec:
        return True

    return False

def insert_ioc_info(rec, ioc_type, ioc_value):
    """ Insert ioc info to a record and also remove duplicated IOC info.

    Args:
        rec (dict): The parsed payload of a log
        ioc_type (str): IOC type, can be 'ip', 'domain' or 'md5'
        ioc_value (str): Matched IOC value from the rec

    Returns:
        (None): rec will be modified with IOC info.
        Example that a record will be inserted with new field "streamalert:ioc":
            "streamalert:ioc": {
                "ip": [
                    "4.3.2.1",
                    "1.2.3.4"
                ],
                "domain" : [
                    "evil1.com",
                    "evil2.com"
                ]
              }
    """
    if StreamThreatIntel.IOC_KEY in rec:
        if (ioc_type in rec[StreamThreatIntel.IOC_KEY] and
                ioc_value not in rec[StreamThreatIntel.IOC_KEY][ioc_type]):
            rec[StreamThreatIntel.IOC_KEY][ioc_type].append(ioc_value)
        else:
            rec[StreamThreatIntel.IOC_KEY][ioc_type] = [ioc_value]
    else:
        rec.update({
            StreamThreatIntel.IOC_KEY: {
                ioc_type: [ioc_value]
            }
        })

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

def data_has_value(data, search_value):
    """Recursively search for a given value
    Args:
        data (dict, list, primitive)
        search_value (string)
    Returns:
        (bool) True or False if found
    """
    if isinstance(data, list):
        return any(data_has_value(item, search_value) for item in data)

    if isinstance(data, dict):
        return any(data_has_value(v, search_value) for v in data.values())

    return data == search_value

def data_has_value_with_substring(data, search_value):
    """Recursively search for a value with the given substring
    Args:
        data (dict, list, primitive)
        search_value (string)
    Returns:
        (bool) True or False if found
    """
    if isinstance(data, list):
        return any(data_has_value_with_substring(item, search_value) for item in data)

    if isinstance(data, dict):
        return any(data_has_value_with_substring(v, search_value) for v in data.values())

    return isinstance(data, basestring) and search_value in data

def data_has_value_from_list(data, needle_list):
    """Recursively search for any values that are in the specified list
    Args:
        data (dict, list, primitive)
        needle_list (list)
    Returns:
        (bool) True or False if found
    """
    if isinstance(data, list):
        return any(data_has_value_from_list(item, needle_list) for item in data)

    if isinstance(data, dict):
        return any(data_has_value_from_list(v, needle_list) for v in data.values())

    if not data:
        return False
    return in_set(data, needle_list)

def data_has_value_from_substring_list(data, needle_list):
    """Recursively search for any values that contain a substring from the specified list
    Args:
        data (dict, list, primitive)
        needle_list (list)
    Returns:
        (bool) True or False if found
    """
    if isinstance(data, list):
        return any(data_has_value_from_substring_list(item, needle_list) for item in data)

    if isinstance(data, dict):
        return any(data_has_value_from_substring_list(v, needle_list) for v in data.values())

    if not data:
        return False

    return any(needle in data for needle in needle_list)

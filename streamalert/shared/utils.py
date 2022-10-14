"""Standalone utility functions used by the StreamAlert core."""
from collections import deque

from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError

from streamalert.shared.logger import get_logger
from streamalert.shared.normalize import Normalizer

LOGGER = get_logger(__name__)


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
    except Exception:  # pylint: disable=broad-except
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


def get_first_key(data, search_key, default_value=None):
    """Search for the first occurrence of the given key anywhere in the nested data structure.

    WARNING: Only use this if you are certain the search_key can't occur more than once.

    Args:
        data (dict or list): Record data to search
        search_key (string): The first value associated with this key is returned
        default_value (object): Value which should be returned if no match was found

    Returns:
        (object) First value found or default_value if no match was found
    """
    keys = get_keys(data, search_key, max_matches=1)
    return keys[0] if keys else default_value


# Nested types which should be further examined.
# Predefining this here instead of in get_keys() is a ~15% performance optimization
_CONTAINER_TYPES = (dict, list)


def get_keys(data, search_key, max_matches=-1):
    """Search for a key anywhere in the nested data structure, returning all associated values.

    Example:
        If data = {
            'path': 'ABC',
            'details': {
                'parent': {
                    'path': 'DEF'
                }
            },
            'events': [
                {
                    'path': 'GHI'
                }
            ]
        }
        then get_keys(data, 'path') will return ['ABC', 'DEF', 'GHI'] (in any order)

    Args:
        data (dict or list): Record data to search
        search_key (str): Values associated with this key are returned
        max_matches (int): If > 0, only the first n matches are returned (performance optimization).
            WARNING: Dictionary traversal order is essentially random. Only rely on this shortcut
            if you are certain that there won't be more than n matches for the given key.

    Returns:
        (list) All values (or at most max_matches values) associated with the given key.
            The values in the result can be of any type. In the example above,
            get_keys(data, 'details') returns a list with a single element of type dict.
    """
    # NOTE: This function has been optimized for performance.
    # If you change this function, use timeit to ensure there are no performance regressions.

    # Recursion is generally inefficient due to stack shuffling for each function call/return.
    # Instead, we use a deque (double-ended queue) in a loop: deques have ~O(1) pop/append
    containers = deque()  # A queue of dicts and lists to examine
    containers.append(data)
    results = []
    while containers:
        obj = containers.popleft()

        if isinstance(obj, dict):
            if search_key in obj:
                results.append(obj[search_key])
                if 0 < max_matches == len(results):
                    # We found n matches - return early
                    return results

            # Enqueue all nested dicts and lists for further searching
            for key, val in obj.items():
                # The data may contain normalized keys if data normalization feature is in use.
                # We need to exclude normalization information from the data, otherwise this
                # helper may fetch info from normalization if there are keyname conflict.
                # For example, Key name 'userName' is both existed as a normalized key defined
                # in conf/normalized_types.json and cloudtrail record schemas.
                if key == Normalizer.NORMALIZATION_KEY:
                    continue
                if val and isinstance(val, _CONTAINER_TYPES):
                    containers.append(val)

        else:
            # Obj is a list - enqueue all nested dicts and lists for further searching
            for val in obj:
                if val and isinstance(val, _CONTAINER_TYPES):
                    containers.append(val)
    return results


def get_database_name(config):
    """Get the name of the athena database using the current config settings
    Args:
        config (CLIConfig): Loaded StreamAlert config
    Returns:
        str: The name of the athena database
    """
    prefix = config['global']['account']['prefix']
    athena_config = config['lambda'].get('athena_partitioner_config')

    return athena_config.get('database_name', f'{prefix}_streamalert')


def get_data_file_format(config):
    """Get the data store format using the current config settings
    Args:
        config (CLIConfig): Loaded StreamAlert config
    Returns:
        str: The data store format either "parquet" or "json"
    """
    athena_config = config['lambda'].get('athena_partitioner_config', {})

    return athena_config.get('file_format')

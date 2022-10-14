"""
Copyright 2017-present Airbnb, Inc.

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
import json
import logging
import random
import time
from fnmatch import fnmatch

import pathlib2

from streamalert.shared.utils import (  # pylint: disable=unused-import; Import some utility functions which are useful for rules as well
    get_first_key, get_keys, in_network, valid_ip)

logging.basicConfig()
LOGGER = logging.getLogger('StreamAlert')


def path_matches_any(text, patterns):
    """Check if the text matches any of the given wildcard patterns.

    NOTE: Intended for filepaths with wildcards where fnmatch is too greedy.
    Especially useful in cases where a username in a filepath may need to be wildcarded.

    For example;
    path_matches_any('/Users/foobar/path/to/file', {'/Users/*/path/*/file'}) == True

    Args:
        text (str): Text to examine
        patterns (iterable): Collection of string patterns, compatible with fnmatch (* wildcards)

    Returns:
        bool: True if the text matches at least one of the patterns, False otherwise.
    """
    return any(pathlib2.PurePath(text).match(pattern) for pattern in patterns) if isinstance(text, str) else False


def starts_with_any(text, prefixes):
    """Check if the text starts with any of the given prefixes.

    For example, starts_with_any('abc', {'a'}) == True
    Functionally equivalent to matches_any() with patterns like 'prefix*', but more efficient

    Args:
        text (str): Text to examine
        prefixes (iterable): Collection of string prefixes (no wildcards)

    Returns:
        bool: True if the text starts with at least one of the given prefixes, False otherwise.
    """
    return any(text.startswith(prefix) for prefix in prefixes) if isinstance(text, str) else False


def ends_with_any(text, suffixes):
    """Check if the text ends with any of the given suffixes.

    For example, ends_with_any('abc', {'c'}) == True
    Functionally equivalent to matches_any() with patterns like '*suffix', but more efficient

    Args:
        text (str): Text to examine
        suffixes (iterable): Collection of string suffixes (no wildcards)

    Returns:
        bool: True if the text ends with at least one of the given prefixes, False otherwise.
    """
    return any(text.endswith(suffix) for suffix in suffixes) if isinstance(text, str) else False


def contains_any(text, substrings):
    """Check if the text contains any of the given substrings.

    For example, contains_any('abc', {'b'}) == True
    Functionally equivalent to matches_any() with patterns like '*substring*', but more efficient

    Args:
        text (str): Text to examine
        substrings (iterable): Collection of string substrings (no wildcards)

    Returns:
        bool: True if the text contains at least one of the given prefixes, False otherwise.
    """
    return any(s in text for s in substrings) if isinstance(text, str) else False


def matches_any(text, patterns):
    """Check if the text matches any of the given wildcard patterns.

    For example, matches_any('abc', {'a*c'}) == True
    WARNING: This is relatively slow and should only be used for complex patterns that can't be
    expressed with contains_any(), starts_with_any(), or ends_with_any()

    Args:
        text (str): Text to examine
        patterns (iterable): Collection of string patterns, compatible with fnmatch (* wildcards)

    Returns:
        bool: True if the text matches at least one of the patterns, False otherwise.
    """
    return any(fnmatch(text, pattern) for pattern in patterns) if isinstance(text, str) else False


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


def data_has_value(data, search_value):
    """Recursively search for a given value.

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

    return isinstance(data, str) and search_value in data


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

    return matches_any(data, needle_list) if data else False


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

    return any(needle in data for needle in needle_list) if data else False


def safe_json_loads(data):
    """Safely load a JSON string into a dictionary

    Args:
        data (str): A JSON string

    Returns:
        dict: The loaded JSON string or empty dict
    """
    try:
        return json.loads(data)
    except ValueError:
        return {}


def random_bool(probability_of_true):
    """Randomly return True or False based on the given probability.

    Useful for very noisy rules where you only want a sample of the matches.

    Args:
        probability_of_true (float): Probability that True should be returned (between 0 and 1).

    Returns:
        (bool) True or False
    """
    if probability_of_true < 0 or probability_of_true > 1:
        raise ValueError('Probability must be between 0.0 and 1.0')
    return random.random() <= probability_of_true

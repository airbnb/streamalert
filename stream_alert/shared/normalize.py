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
import logging

from stream_alert.shared.config import TopLevelConfigKeys
from stream_alert.shared.logger import get_logger


LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)


class Normalizer(object):
    """Normalizer class to handle log key normalization in payloads"""

    NORMALIZATION_KEY = 'streamalert:normalization'

    # Store the normalized CEF types mapping to original keys from the records
    _types_config = dict()

    @classmethod
    def match_types(cls, record, normalized_types):
        """Check for normalized types within record

        Args:
            record (dict): Parsed payload of log
            normalized_types (dict): Normalized types mapping

        Returns:
            dict: A dict of normalized keys with a list of values

        Example:
            record={
                'region': 'us-east-1',
                'detail': {
                    'awsRegion': 'us-west-2'
                }
            }
            normalized_types={
                'region': ['region', 'awsRegion']
            }

            return={
                'region': ['us-east-1', 'us-west-2']
            }
        """
        return {
            key: sorted(set(cls._extract_values(record, set(keys_to_normalize))))
            for key, keys_to_normalize in normalized_types.iteritems()
        }

    @classmethod
    def _extract_values(cls, record, keys_to_normalize):
        """Recursively extract lists of path parts from a dictionary

        Args:
            record (dict): Parsed payload of log
            keys_to_normalize (set): Normalized keys for which to extract paths
            path (list=None): Parts of current path for which keys are being extracted

        Yields:
            list: Parts of path in dictionary that contain normalized keys
        """
        for key, value in record.iteritems():
            if isinstance(value, dict):  # If this is a dict, look for nested
                for nested_value in cls._extract_values(value, keys_to_normalize):
                    yield nested_value

            if key not in keys_to_normalize:
                continue

            if isinstance(value, list):  # If this is a list of values, return all of them
                for item in value:
                    yield item
            else:
                yield value

    @classmethod
    def normalize(cls, record, log_type):
        """Apply data normalization to a record

        Args:
            record (dict): The parsed log without data normalization
            log_type (str): Type of log for which to apply normalizaiton
        """
        log_normalized_types = cls._types_config.get(log_type)
        if not log_normalized_types:
            LOGGER.debug('No normalized types defined for log type: %s', log_type)
            return

        # Add normalized keys to the record
        record.update({cls.NORMALIZATION_KEY: cls.match_types(record, log_normalized_types)})

    @classmethod
    def get_values_for_normalized_type(cls, record, datatype):
        """Fetch values by normalized_type.

        Args:
            record (dict): parsed payload of any log
            datatype (str): normalized type being found

        Returns:
            set: The values for the normalized type specified
        """
        return set(record.get(cls.NORMALIZATION_KEY, {}).get(datatype, set()))

    @classmethod
    def load_from_config(cls, config):
        """Extract and store the data types from the config in the proper format

        Args:
            config (dict): Config read from 'conf/' directory

        Returns:
            Normalizer: Class to be used for normalization logic
        """
        if cls._types_config:
            return cls  # config is already populated

        if TopLevelConfigKeys.NORMALIZED_TYPES not in config:
            return cls  # nothing to do

        cls._types_config = config[TopLevelConfigKeys.NORMALIZED_TYPES]

        return cls  # there are no instance methods, so just return the class

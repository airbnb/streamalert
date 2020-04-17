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
from collections import defaultdict
import logging

from streamalert.shared.config import TopLevelConfigKeys
from streamalert.shared.exceptions import ConfigError
from streamalert.shared.logger import get_logger


LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)


class Normalizer:
    """Normalizer class to handle log key normalization in payloads"""

    NORMALIZATION_KEY = 'streamalert:normalization'
    NORMALIZATION_FIELDS = 'fields'
    NORMALIZATION_FUNCTION = 'function'
    NORMALIZATION_VALUES = 'values'

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

        FIXME: update example
        Example:
            {
              'record': {
                  'region': 'us-east-1',
                  'detail': {
                      'awsRegion': 'us-west-2'
                  }
              },
              'normalization': {
                  'region': {
                      'values': ['us-east-1', 'us-west-2']
                      'function': 'AWS region'
                  }
              }
            }

            return
            {
                'region': {
                    'values': ['us-east-1', 'us-west-2']
                    'function': 'AWS region'
                }
            }
        """
        result = {}
        for key, keys_to_normalize in normalized_types.items():
            values = set()
            for value in cls._extract_values(
                    record, set(keys_to_normalize.get(cls.NORMALIZATION_FIELDS, []))
                ):
                # Skip emtpy values
                if value is None or value == '':
                    continue

                values.add(value)

            if not values:
                continue

            result[key] = {
                cls.NORMALIZATION_VALUES: sorted(values, key=str),
                cls.NORMALIZATION_FUNCTION: keys_to_normalize.get(cls.NORMALIZATION_FUNCTION)
            }

        return result

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
        for key, value in record.items():
            if isinstance(value, dict):  # If this is a dict, look for nested
                for nested_value in cls._extract_values(value, keys_to_normalize):
                    yield nested_value
                continue

            if key not in keys_to_normalize:
                continue

            if isinstance(value, list):  # If this is a list of values, return all of them
                for item in value:
                    yield item
                continue

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
        # return set(record.get(cls.NORMALIZATION_KEY, {}).get(datatype, set()))
        return set(
            record.get(
                cls.NORMALIZATION_KEY, {}
            ).get(datatype, {}).get(cls.NORMALIZATION_VALUES, set())
        )

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

        cls._types_config = cls._load_types_config(config)

        return cls  # there are no instance methods, so just return the class

    @classmethod
    def _load_types_config(cls, config):
        """Load normalization config both from "logs" and "normalized_types" fields in the config

        Args:
            config (dict): Config read from 'conf/' directory

        Returns:
            dict: Return merged normalization config in the format of
            {
                'cloudwatch:events': {
                    'region': {
                        'fields': [
                            'region',
                            'awsRegion'
                        ]
                    },
                    'sourceAccount': {
                        'fields': [
                            'account',
                            'accountId'
                        ]
                    },
                    'sourceAddress': {
                        'fields': [
                            'source',
                            'sourceIPAddress'
                        ],
                        'function': 'source ip address'
                    }
                }
            }
        """
        # the merged_normalization will have following structure
        # {
        #     'cloudwatch:events': {
        #         'sourceAccount': ['account', 'accountId'],
        #         'sourceAddress': {
        #             'fields': ['source', 'sourceIPAddress'],
        #             'function': 'source ip address'
        #         }
        #     }
        # }
        merged_normalization = cls._merge_normalization(config)

        types_config = defaultdict(dict)
        for log_type, normalized_types in merged_normalization.items():
            type_config = defaultdict(dict)
            for key, val in normalized_types.items():
                if isinstance(val, list):
                    # The normalized type only contains original keys in a list.
                    type_config[key][cls.NORMALIZATION_FIELDS] = val
                elif isinstance(val, dict):
                    # The normalized type has rich definition including "fields" and
                    # "function" information.
                    type_config[key] = val
                else:
                    raise ConfigError(
                        'Invalid value type "{}" defiend for {}'.format(type(val), log_type)
                    )

            types_config[log_type] = type_config

        if not types_config:
            return

        return types_config

    @classmethod
    def _merge_normalization(cls, config):
        """Merge normalization config from "logs" and "normalization" fields in the config

        In Normalization v1, the normalized types are defined in conf/normalized_types.json and it
        is log source based, e.g. osquery, cloudwatch.

        In Normalization v2, the normalized types are defined in conf/logs.json or conf/schemas/ and
        it is log type based, e.g. osquery:differential, cloudwatch:events, cloudwatch:cloudtrail.

        Both definitions are valid and they will be merged to provide backward compatiblility and
        flexibility.

        Args:
            config (dict): Config read from 'conf/' directory

        Returns:
            dict: return merged normalization information with following structure
                {
                    'cloudwatch:events': {
                        'sourceAccount': ['account', 'accountId'],
                        'sourceAddress': {
                            'fields': ['source', 'sourceIPAddress'],
                            'function': 'source ip address'
                        }
                    }
                }
        """
        normalized_config = defaultdict(dict)
        for log_type, val in config.get(TopLevelConfigKeys.LOGS, {}).items():
            log_type_normalization = val.get('configuration', {}).get('normalization')

            if log_type_normalization:
                # add normalization info if it is defined in log type configuration field
                normalized_config[log_type] = log_type_normalization

            # osquery is the log_source of log type "osquery:differential"
            log_source = log_type.split(':')[0]

            if not config.get(TopLevelConfigKeys.NORMALIZED_TYPES):
                # skip if config['normalized_types'] doesn't exist
                continue

            if log_source not in config.get(TopLevelConfigKeys.NORMALIZED_TYPES):
                # skip if the log source has no normalized types defined in
                # config['normalized_types']
                continue

            if normalized_config.get(log_type):
                normalized_config[log_type].update(
                    config[TopLevelConfigKeys.NORMALIZED_TYPES][log_source]
                )
            else:
                normalized_config[log_type] = (
                    config[TopLevelConfigKeys.NORMALIZED_TYPES][log_source]
                )

        return normalized_config

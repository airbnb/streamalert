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
import itertools

from streamalert.shared.config import TopLevelConfigKeys
from streamalert.shared.exceptions import ConfigError
from streamalert.shared.logger import get_logger


LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)

class NormalizedType:
    """The class encapsulates normalization information for each normalized type"""

    VALID_KEYS = {'fields', 'function'}
    CONST_STR = 'str'
    CONST_DICT = 'dict'

    def __init__(self, log_type, normalized_type, params):
        """Init NormalizatedType
        Args:
            log_type (str): log type name, e.g. osquery:differential
            normalized_type (str): Normalized type name defined in conf/, e.g. 'sourceAddress',
                'destination_ip' may be normalized to 'ip_address'.
            params (list): a list of str or dict contains normalization configuration.
                When it is read from conf/normalized_type.json, the params is a list of str, e.g.
                    ['ipv4', 'local_ip']
                When it is read from conf/schemas/*.json, the params should be a list of dictionary
                having following format, otherwise it will raise ConfigError.
                    [
                        {
                            'fields': ['source', 'sourceIPAddress'],
                            'function': 'source ip address'
                        },
                        {
                            'fields': ['destination'],
                            'function': 'destination ip address'
                        }
                    ]
        """
        self._log_type = log_type
        self._log_source = log_type.split(':')[0]
        self._normalized_type = normalized_type
        self._parsed_params = self._parse_params(params)

    def __eq__(self, other):
        """Compare two NormalizedType instances and it is very helpful in unit test when use
        assert_equal
        """
        if not (self._log_type == other.log_type
                and self._log_source == other.log_source
                and self._normalized_type == other.normalized_type):
            return False

        if len(self._parsed_params) != len(other.parsed_params):
            return False

        for idx in range(len(self._parsed_params)):
            if self._parsed_params[idx]['fields'] == other.parsed_params[idx]['fields']:
                continue

            return False

        return True

    @property
    def log_type(self):
        """Return the log type name, e.g. 'osquery:differential'"""
        return self._log_type

    @property
    def log_source(self):
        """Return the log source name, e.g. 'osquery'"""
        return self._log_source

    @property
    def normalized_type(self):
        """Return the normalized type, e.g. 'ip_address'"""
        return self._normalized_type

    @property
    def parsed_params(self):
        """Return the normalization configuration which is a list of dict, e.g.
            [
                {
                    'fields': {'account', 'accountId'},
                    'function': None
                }
            ]

            or
            [
                {
                    'fields': {'source', 'sourceIPAddress'},
                    'function': 'source ip address'
                },
                {
                    'fields': {'destination'},
                    'function': 'destination ip address'
                }
            ]
        """
        return self._parsed_params

    def _parse_params(self, params):
        """Extract fields and function information from params argument

        Args:
            params (list): a list of str or dict contains normalization configuration.
        """
        param_type = self._parse_param_type(params)

        # When it is read from conf/normalized_type.json, the params is a list of str.
        # When it is read from conf/schemas/*.json, the params should be a list of dictionary
        # containing 'fields' and 'function' information for normalized types
        if param_type == self.CONST_STR:
            return [
                {
                    'fields': set(params),
                    'function': None
                }
            ]

        for param in params:
            # Use set to remove duplicated value in 'fields'
            param['fields'] = set(param['fields'])

        return params

    def _parse_param_type(self, params):
        """Parse all param type in params

        Args:
            params (list): a list of str or dict contains normalization configuration.
        """
        if not isinstance(params, list):
            raise ConfigError(
                'Unsupported params {} for normalization. Convert params to a list'.format(params)
            )

        if all(isinstance(param, str) for param in params):
            return self.CONST_STR

        if all(isinstance(param, dict) and set(param.keys()) == self.VALID_KEYS
               for param in params
              ):
            return self.CONST_DICT

        # FIXME: should we raise exception here? Or may just return False and log a warming message
        raise ConfigError(
            ('Unsupported type(s) used in {} or missing keys. Valid types are str or dict and '
             'valid keys are {}').format(params, self.VALID_KEYS)
        )

    def update(self, params):
        """Update parsed_params attribute.

        This method will be only called when merging normalization v1 configuration
        (conf/normalized_types.json) into v2.
        """
        param_type = self._parse_param_type(params)
        if param_type == self.CONST_STR:
            self._deduplicate_params(params)
            if not params:
                # Do nothing if the key exist in self._parsed_params
                return

            # New params will be added to the entry has no 'function' information otherwise add a
            # new entry.
            for parsed_param in self._parsed_params:
                if not parsed_param.get('function'):
                    parsed_param['fields'].update(params)
                    return

            # Add a new entry to parsed_params attribute and set 'function' field to None
            self._parsed_params.append({
                'fields': set(params),
                'function': None
            })
        else:
            raise ConfigError(
                ('Unexpected type detected. It only supports a list of string, but get a list of '
                 '{} in params {}'.format(param_type, params))
            )

    def _deduplicate_params(self, params):
        """Remove duplicated keys from params"""
        # Flatten all keys from the 'fields' to a list
        # e.g. self._parse_params = [
        #     {
        #         'fields': {'source', 'sourceIPAddress'},
        #         'function': 'source ip address'
        #     },
        #     {
        #         'fields': {'destination'},
        #         'function': 'destination ip address'
        #     }
        # ]
        # all_fields will be ['source', 'sourceAddress', 'destination']
        all_fields = list(
            itertools.chain(*[parsed_param.get('fields') for parsed_param in self._parsed_params])
        )

        for param in params:
            if param in all_fields:
                params.remove(param)


class Normalizer:
    """Normalizer class to handle log key normalization in payloads"""

    NORMALIZATION_KEY = 'streamalert:normalization'
    NORMALIZATION_FIELDS = 'fields'
    NORMALIZATION_FUNCTION = 'function'
    NORMALIZATION_VALUES = 'values'

    # Store the normalized types mapping to original keys from the records
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
        for key, normalized_type in normalized_types.items():
            for parsed_param in normalized_type.parsed_params:
                values = set()
                # Yikes, 3rd for loop.
                for value in cls._extract_values(
                        record, set(parsed_param.get(cls.NORMALIZATION_FIELDS, []))
                    ):
                    # Skip emtpy values
                    if value is None or value == '':
                        continue

                    values.add(value)

                if not values:
                    continue

                result[key] = {
                    cls.NORMALIZATION_VALUES: sorted(values, key=str),
                    cls.NORMALIZATION_FUNCTION: parsed_param.get(cls.NORMALIZATION_FUNCTION)
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

        cls._types_config = cls._merge_normalization(config)

        return cls  # there are no instance methods, so just return the class

    @classmethod
    def _merge_normalization(cls, config):
        """Merge normalization config from conf/schemas/*.json and conf/normalized_types.json

        In Normalization v1, the normalized types are defined in conf/normalized_types.json and it
        is log source based, e.g. osquery, cloudwatch.

        In Normalization v2, the normalized types are defined in conf/logs.json or conf/schemas/ and
        it is log type based, e.g. osquery:differential, cloudwatch:events, cloudwatch:cloudtrail.

        Both definitions are valid and they will be merged to provide backward compatiblility and
        flexibility.

        Args:
            config (dict): Config read from 'conf/' directory

            conf/schemas/cloudwatch.json looks like (preferred in Normalization v2)
                'cloudwatch:events': {
                    'schema': {
                        'account': 'string',
                        'source': 'string',
                        'other_key': 'string'
                    },
                    'configuration': {
                        'normalization': {
                            'region': ['awsRegion'],
                            'ip_address': [
                                {
                                    'fields': ['source', 'sourceIPAddress'],
                                    'function': 'source ip address'
                                },
                                {
                                    'fields': ['destination'],
                                    'function': 'destination ip address'
                                }
                            ]
                        }
                    }
                }

            conf/normalized_types.json looks like
                'cloudwatch': {
                    'region': ['region', 'awsRegion'],
                    'sourceAccount': ['account', 'accountId']
                }

        Returns:
            dict: return merged normalization configuration with following structure
                {
                    'cloudwatch:events': {
                        'region': NormalizedType(
                            'cloudwatch:events',
                            'region',
                            ['region', 'awsRegion']),
                        'sourceAccount': NormalizedType(
                            'cloudwatch:events',
                            'sourceAccount',
                            ['account', 'accountId']
                        ),
                        'ip_address': NormalizedType(
                            'cloudwatch:events',
                            'ip_address',
                            [
                                {
                                    'fields': ['source', 'sourceIPAddress'],
                                    'function': 'source ip address'
                                },
                                {
                                    'fields': ['destination'],
                                    'function': 'destination ip address'
                                }
                            ]
                        )
                    }
                }
        """
        normalized_config = defaultdict(dict)
        for log_type, val in config.get(TopLevelConfigKeys.LOGS, {}).items():
            result = defaultdict(dict)

            log_type_normalization = val.get('configuration', {}).get('normalization', {})

            for normalized_type, params in log_type_normalization.items():
                # add normalization info if it is defined in log type configuration field
                result[normalized_type] = NormalizedType(log_type, normalized_type, params)

            # osquery is the log_source of log type "osquery:differential"
            log_source = log_type.split(':')[0]

            if not cls._normalized_types_field(log_source, config) and result:
                normalized_config[log_type] = result
                continue

            # Merge from config['normalized_types'], loading from conf/normalized_types.json
            for normalized_type, params in config[TopLevelConfigKeys.NORMALIZED_TYPES].get(
                    log_source, {}
                ).items():
                if normalized_type in result:
                    # FIXME: maybe can use defaultdict(NormalizedType)
                    result[normalized_type].update(params)
                else:
                    result[normalized_type] = NormalizedType(log_type, normalized_type, params)

            if result:
                normalized_config[log_type] = result

        # return None is normalized_config is an empty defaultdict.
        return normalized_config or None

    @classmethod
    def _normalized_types_field(cls, log_source, config):
        """Check if "normalized_types" field exists and the log_source defined in the conf"""
        return (
            config.get(TopLevelConfigKeys.NORMALIZED_TYPES)
            and log_source in config.get(TopLevelConfigKeys.NORMALIZED_TYPES)
        )

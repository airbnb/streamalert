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
import itertools
import logging
import uuid
from collections import defaultdict

from streamalert.shared.config import TopLevelConfigKeys
from streamalert.shared.exceptions import ConfigError
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)

CONST_FUNCTION = 'function'
CONST_PATH = 'path'
CONST_CONDITION = 'condition'
CONST_VALUES = 'values'
CONST_ARTIFACTS_FLAG = 'send_to_artifacts'


class NormalizedType:
    """The class encapsulates normalization information for each normalized type"""

    VALID_KEYS = {CONST_PATH, CONST_FUNCTION, CONST_CONDITION, CONST_ARTIFACTS_FLAG}
    CONST_STR = 'str'
    CONST_DICT = 'dict'

    def __init__(self, log_type, normalized_type, params):
        """Init NormalizatedType
        Args:
            log_type (str): log type name, e.g. osquery:differential
            normalized_type (str): Normalized type name defined in conf/, e.g. 'sourceAddress',
                'destination_ip' may be normalized to 'ip_address'.
            params (list): a list of str or dict contains normalization configuration read from
                conf/schemas/*.json. The params can be a list of str or a list of dict to specify
                the path to the keys which will be normalized.
                e.g.
                    ['path', 'to', 'the', 'key']
                or
                    [
                        {
                            'path': ['detail', 'sourceIPAddress'],
                            'function': 'source ip address'
                        },
                        {
                            'path': ['path', 'to', 'the', 'key'],
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
        if not (self._log_type == other.log_type and self._log_source == other.log_source
                and self._normalized_type == other.normalized_type):
            return False

        if len(self._parsed_params) != len(other.parsed_params):
            return False

        return all(self._parsed_params[idx][CONST_PATH] == other.parsed_params[idx][CONST_PATH]
                   for idx in range(len(self._parsed_params)))

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
                    'path': ['path', 'to', 'the', 'key'],
                    'function': None
                }
            ]

            or
            [
                {
                    'path': ['detail', 'sourceIPAddress'],
                    'function': 'source ip address',
                    'send_to_artifacts': False
                },
                {
                    'path': ['path', 'to', 'the', 'destination', 'ip'],
                    'function': 'destination ip address'
                }
            ]
        """
        return self._parsed_params

    def _parse_params(self, params):
        """Extract path and function information from params argument

        Args:
            params (list): a list of str or dict contains normalization configuration.
        """
        param_type = self._parse_param_type(params)

        if param_type == self.CONST_STR:
            # Format params to include 'function' field which is set to None.
            return [{CONST_PATH: params, CONST_FUNCTION: None}]

        return params

    def _parse_param_type(self, params):
        """Parse all param type in params

        Args:
            params (list): a list of str or dict contains normalization configuration.
        """
        if not isinstance(params, list):
            raise ConfigError(
                f'Unsupported params {params} for normalization. Convert params to a list')

        if all(isinstance(param, str) for param in params):
            return self.CONST_STR

        if all(
                isinstance(param, dict) and set(param.keys()).issubset(self.VALID_KEYS)
                for param in params):
            return self.CONST_DICT

        # FIXME: should we raise exception here? Or may just return False and log a warming message
        raise ConfigError(
            f'Unsupported type(s) used in {params} or missing keys. Valid types are str or dict and valid keys are {self.VALID_KEYS}'
        )


class Normalizer:
    """Normalizer class to handle log key normalization in payloads"""

    NORMALIZATION_KEY = 'streamalert_normalization'
    RECORD_ID_KEY = 'streamalert_record_id'

    # Store the normalized types mapping to original keys from the records
    _types_config = {}

    @classmethod
    def match_types(cls, record, normalized_types):
        """Check for normalized types within record

        Args:
            record (dict): Parsed payload of log
            normalized_types (dict): Normalized types mapping

        Returns:
            dict: A dict of normalized keys with a list of values

        Example:
            return
            {
                'region': [
                    {
                        'values': ['us-east-1']
                        'function': 'AWS region'
                    },
                    {
                        'values': ['us-west-2']
                        'function': 'AWS region'
                    }
                ]
            }
        """
        results = {}
        for type_name, type_info in normalized_types.items():
            if result := list(cls._extract_values(record, type_info)):
                results[type_name] = result

        if results:
            results[cls.RECORD_ID_KEY] = str(uuid.uuid4())
        return results

    @classmethod
    def _find_value(cls, record, path):
        """Retrieve value from a record based on a json path"""
        found_value = False
        value = record
        for key in path:
            value = value.get(key)
            if not value:
                found_value = False
                break
            found_value = True

        return (True, value) if found_value else (False, None)

    @classmethod
    def _extract_values(cls, record, paths_to_normalize):
        """Recursively extract lists of path parts from a dictionary

        Args:
            record (dict): Parsed payload of log
            paths_to_normalize (set): Normalized keys for which to extract paths
            path (list=None): Parts of current path for which keys are being extracted

        Yields:
            dict: A dict contians the values of normalized types. For example,
                {
                    'values': ['1.1.1.2']
                    'function': 'Source ip address'
                }
        """
        for param in paths_to_normalize.parsed_params:
            if param.get(CONST_CONDITION) and not cls._match_condition(
                    record, param[CONST_CONDITION]):
                # If optional 'condition' block is configured, it will only extract values if
                # condition is matched.
                continue

            found_value, value = cls._find_value(record, param.get(CONST_PATH))

            if found_value:
                result = {
                    CONST_FUNCTION: param.get(CONST_FUNCTION) or None,
                    # if value not a list, it will be cast to a str even it is a dict or other
                    # types
                    CONST_VALUES: value if isinstance(value, list) else [str(value)]
                }

                # Add "send_to_artifacts" flag to the normalized field when it explicitly sets the
                # flag to "false" in the normalizer in conf/schemas/*.json
                if not param.get(CONST_ARTIFACTS_FLAG, True):
                    result[CONST_ARTIFACTS_FLAG] = False

                yield result

    @classmethod
    def _match_condition(cls, record, condition):
        """Apply condition to a record before normalization kicked in.

        Returns:
            bool: Return True if the value of the condition path matches to the condition, otherwise
                return False. It is False if the path doesn't exist.
        """
        if not condition.get(CONST_PATH):
            return False

        found_value, value = cls._find_value(record, condition[CONST_PATH])
        if not found_value:
            return False

        # cast value to a str in all lowercases
        value = str(value).lower()

        # Only support extract one condition. The result is not quaranteed if multiple conditions
        # configured.
        # FIXME: log a warning if more than one condition configured.
        if condition.get('is'):
            return value == condition['is']

        if condition.get('is_not'):
            return value != condition['is_not']

        if condition.get('in'):
            return value in condition['in']

        if condition.get('not_in'):
            return value not in condition['not_in']

        if condition.get('contains'):
            return condition['contains'] in value

        if condition.get('not_contains'):
            return condition['not_contains'] not in value

        return False

    @classmethod
    def normalize(cls, record, log_type):
        """Apply data normalization to a record

        Args:
            record (dict): The parsed log without data normalization
            log_type (str): Type of log for which to apply normalizaiton
        """
        log_normalized_types = cls._types_config.get(log_type) if cls._types_config else None
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
        normalization_results = record.get(cls.NORMALIZATION_KEY, {}).get(datatype)
        return set(itertools.chain(
            *[result.get(CONST_VALUES)
              for result in normalization_results])) if normalization_results else set()

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

        cls._types_config = cls._parse_normalization(config)

        return cls  # there are no instance methods, so just return the class

    @classmethod
    def _parse_normalization(cls, config):
        """Load and parse normalization config from conf/schemas/*.json. Normalization will be
        configured along with log schema and a path will be provided to find the original key.

        For example: conf/schemas/cloudwatch.json looks like
            'cloudwatch:events': {
                'schema': {
                    'account': 'string',
                    'source': 'string',
                    'other_key': 'string'
                },
                'configuration': {
                    'normalization': {
                        'region': ['path', 'to', 'original', 'key'],
                        'ip_address': [
                            {
                                'path': ['detail', 'sourceIPAddress'],
                                'function': 'source ip address'
                            },
                            {
                                'path': ['path', 'to', 'original', 'key'],
                                'function': 'destination ip address'
                            }
                        ]
                    }
                }
            }

        Args:
            config (dict): Config read from 'conf/' directory

        Returns:
            dict: return a dict contains normalization information per log type basis.
                {
                    'cloudwatch:events': {
                        'region': NormalizedType(),
                        'ip_address': NormalizedType()
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

            if result:
                normalized_config[log_type] = result

        # return None is normalized_config is an empty defaultdict.
        return normalized_config or None

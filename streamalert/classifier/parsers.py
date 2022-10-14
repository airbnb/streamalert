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
import csv
import io
import json
import logging
import re
from abc import ABCMeta, abstractmethod
from copy import deepcopy
from fnmatch import fnmatch

import jmespath

from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)
PARSERS = {}


def parser(cls):
    """Class decorator to register parsers"""
    # Currently supported parsers are json, csv, kv, and syslog
    parser_type = cls.type()
    if not parser_type:
        raise NotImplementedError(
            f"{cls.__name__}: Parser does not define a class property for \'_type\'")

    PARSERS[parser_type] = cls
    return cls


def get_parser(parser_type):
    """Helper method to fetch parser classes

    Args:
        parser_type (string): the name of the parser class to get

    Returns:
        A Parser class
    """
    return PARSERS[parser_type]


class ParserBase(metaclass=ABCMeta):
    """Abstract Parser class to be inherited by all StreamAlert Parsers"""
    _type = None

    ENVELOPE_KEY = 'streamalert:envelope_keys'
    _TYPE_MAP = {'string': str, 'integer': int, 'float': float, 'boolean': bool}

    def __init__(self, options, log_type=None):
        """Setup required parser properties

        Args:
            options (dict): Parser options - delimiter, separator, or log_patterns
        """
        self._options = options or {}
        self._schema_type = log_type
        self._valid_parses = []
        self._invalid_parses = []

    def __bool__(self):
        return self.valid

    def __len__(self):
        return len(self._valid_parses)

    @classmethod
    def type(cls):
        """Returns the type of parser"""
        return cls._type

    @property
    def _schema(self):
        return self._options.get('schema', {})

    @property
    def _configuration(self):
        return self._options.get('configuration', {})

    @property
    def _optional_top_level_keys(self):
        return set(self._configuration.get('optional_top_level_keys', {}))

    @property
    def _log_patterns(self):
        return self._configuration.get('log_patterns')

    @property
    def _json_path(self):
        return self._configuration.get('json_path')

    @property
    def _envelope_schema(self):
        return self._configuration.get('envelope_keys', {})

    @property
    def _optional_envelope_keys(self):
        return set(self._configuration.get('optional_envelope_keys', {}))

    @property
    def valid(self):
        return len(self._valid_parses) != 0

    @property
    def log_schema_type(self):
        return self._schema_type

    @property
    def invalid_parses(self):
        return self._invalid_parses

    @property
    def parsed_records(self):
        return self._valid_parses

    @classmethod
    def default_optional_values(cls, key):
        """Return a default value for a given supported schema type"""
        # Return instances of types that are defined, or of the type being passed in
        return cls._TYPE_MAP[key]() if isinstance(key, str) else type(key)()

    @classmethod
    def _apply_envelope(cls, record, envelope):
        """Apply the envelope extracted from the orignal record to the parsed record

        Args:
            record (dict): Value of the successfully parsed record
            envelope (dict): Extracted envelope to be added to the parsed record
        """
        if not envelope:
            return

        record.update({cls.ENVELOPE_KEY: envelope})

    @classmethod
    def _add_optional_keys(cls, data, schema, optional_keys):
        """Add optional keys to a raw record

        Args:
            data (dict): Parsed record value
            schema (dict): Schema for the data being parsed
            optional_keys (set): The optional keys in the schema
        """
        if not (schema and optional_keys):
            return  # Nothing to do

        for key_name in optional_keys:
            # Add the optional key if it does not exist in the parsed json payload
            data[key_name] = data.get(key_name, cls.default_optional_values(schema[key_name]))

    @classmethod
    def _matches_log_patterns(cls, record, log_patterns, envelope=None):
        """Check if all log patterns specified for this record match

        Args:
            record (dict): Parsed record value
            log_patterns (dict): Log patterns that should be enforced for the data
            being parsed. This could be checking a nested value, so it should be
            passed in as an argument.

        Returns:
            bool: True if all specified log patterns match, False otherwise
        """
        # Return True immediately if there are no log patterns
        if not log_patterns:
            return True

        result = True
        for field, patterns in log_patterns.items():
            if field == cls.ENVELOPE_KEY:
                return cls._matches_log_patterns(envelope, patterns)

            # handle nested log_patterns
            if isinstance(patterns, dict):
                return cls._matches_log_patterns(record[field], patterns)

            # Transform a flat pattern into a list
            if isinstance(patterns, str):
                LOGGER.debug('Transforming flat pattern \'%s\' into list', patterns)
                patterns = [patterns]

            # Ensure the pattern key is in the record
            if field not in record:
                LOGGER.error('Declared log pattern key [%s] does exist in record:\n%s', field,
                             record)
                return False

            value = record.get(field)

            # Ensure at least one of the log_patterns matches
            result = result and any(fnmatch(value, pattern) for pattern in patterns)

        LOGGER.debug('%s log pattern match result: %s', cls.type(), result)

        # If all pattern match results are True
        return result

    @classmethod
    def _key_check(cls, record, schema, optionals=None, is_envelope=False):
        """Verify the declared schema matches the record

        Args:
            record (dict): Parsed record value
            schema (dict): Schema for the data being parsed. This could be parsing
                a nested value, so it should be passed in as an argument.
            optionals (set=None): Set of optional keys in the passed in schema that
                should be excluded from the key checking.
            is_envelope (bool=False): Set to True if this is validating the envelope
                keys and not the parsed record keys. Envelope keys only have to be a
                subset of the entire envelope, so simply check for that.

        Returns:
            bool: True if the log matches the schema, False if not
        """
        # Nothing to do for empty schema. This happens in the case of nested schema validation
        if not schema:
            return True

        # Expect the record is a dict. Return False (schema doesn't match) if it is not.
        if not isinstance(record, dict):
            return False

        schema_keys = set(schema)

        keys = set(record).union(optionals) if optionals else set(record)

        if is_envelope and not schema_keys.issubset(keys):
            LOGGER.debug('Missing keys in record envelope: %s', schema_keys - keys)
            return False

        if not is_envelope and keys != schema_keys:
            if expected := schema_keys - keys:
                LOGGER.debug('Expected keys not found in record: %s',
                             ', '.join(str(val) for val in sorted(expected, key=str)))

            if found := keys - schema_keys:
                LOGGER.debug('Found keys not expected in record: %s',
                             ', '.join(str(val) for val in sorted(found, key=str)))
            return False

        # Nested key check
        match = True
        for key, key_type in schema.items():
            # Skip any value that is not a dictionary
            if not isinstance(key_type, dict):
                continue

            # Nested key check, these cannot support optionals currently
            # Use a default dict value in case this key is optional
            match = match and cls._key_check(record.get(key, {}), key_type)

        if not match and LOGGER_DEBUG_ENABLED:
            LOGGER.debug('Nested key check failure. Schema:\n%s\nRecord:\n%s',
                         json.dumps(schema, indent=2, sort_keys=True),
                         json.dumps(record, indent=2, sort_keys=True))

        return match

    @classmethod
    def _convert_type(cls, record, schema, optionals=None):
        """Convert a parsed payload's values into their declared types.

        If the schema is incorrectly defined for a particular field,
        this function will return False which will make the payload
        invalid.

        Args:
            record (dict): Parsed record value
            schema (dict): Schema for the data being parsed. This could be parsing
                a nested value, so it should be passed in as an argument.
            optionals (set=None): Set of optional keys in the passed in schema that
                should be excluded from type conversion if not present in the record.

        Returns:
            bool: True if type conversion was successful, False otherwise
        """
        for key, value in schema.items():
            key = str(key)

            # No need to type an optional key if it's value is not in the
            # record since this is a value we will insert
            if optionals and key in optionals and key not in record:
                LOGGER.debug('Skipping optional key not found in record: %s', key)
                continue

            if not record[key]:
                LOGGER.debug('Skipping NoneType value in record for key: %s', key)
                continue

            # if the schema value is declared as string
            if value == 'string':
                try:
                    record[key] = str(record[key])
                except UnicodeEncodeError:
                    record[key] = str(record[key])

            # if the schema value is declared as integer
            elif value == 'integer':
                try:
                    record[key] = int(record[key])
                except (ValueError, TypeError):
                    LOGGER.error('Invalid schema. Value for key [%s] is not an int: %s', key,
                                 record[key])
                    return False

            elif value == 'float':
                try:
                    record[key] = float(record[key])
                except (ValueError, TypeError):
                    LOGGER.error('Invalid schema. Value for key [%s] is not a float: %s', key,
                                 record[key])
                    return False

            elif value == 'boolean':
                record[key] = str(record[key]).lower() == 'true'

            elif isinstance(value, dict):
                # Convert nested types
                if not cls._convert_type(record[key], value):
                    return False

            elif isinstance(value, list):
                # Ensure a list is actually a list, but do not check list value types
                # since we do not currently support type checking list elements
                if not isinstance(record[key], list):
                    LOGGER.error('Invalid schema. Value for key [%s] is not a list: %s', key,
                                 record[key])
                    return False

            else:
                LOGGER.error('Unsupported value type in schema for key \'%s\': %s', key, value)
                return False

        return True

    def _validate_schema(self):
        """Ensure the schema, including optional keys, etc, is defined properly

        All optional top level keys should also be defined within the schema itself,
        and just included in the optional top level keys list. The same applies to
        optional envelope keys and the envelope keys/schema.

        In the future, this function can be added to so that it also performs validation
        of types defined for values and so forth.

        Returns:
            bool: True if this schema is valid, False otherwise
        """
        # TODO (ryandeivert): check the value of types defined in the schema to ensure
        # they are valid before erroring out at the _convert_type stage
        values = [(self._schema, self._optional_top_level_keys),
                  (self._envelope_schema, self._optional_envelope_keys)]

        return all(optionals.issubset(schema) for schema, optionals in values)

    def _add_parse_result(self, record, valid, envelope):
        """Add the result of parsing to the proper array, updating the envelope in the process

        Args:
            record (dict): Value of the parsed (or unparsed, if failed) record
            valid (bool): True if the parsing was successful, False otherwise
            envelope (dict): Extracted envelope to be added to the parsed record
        """
        if not valid:
            self._invalid_parses.append(record)
            return

        self._apply_envelope(record, envelope)
        self._add_optional_keys(record, self._schema, self._optional_top_level_keys)

        self._valid_parses.append(record)

    def _extract_envelope(self, payload):
        """Extract envelope key/values from the original payload

        Args:
            payload (dict): The original record to pull envelope keys from

        Returns:
            dict: Key/values extracted from the log to be used as the envelope
        """
        if not self._envelope_schema:
            return

        LOGGER.debug('Extracting envelope keys')
        return {
            key: payload[key]
            for key in self._envelope_schema
            if key in payload  # This is fine since some of these may be optional
        }

    def _json_path_records(self, payload):
        """Extract records from the original json payload using a provided JSON path

        Args:
            payload (dict): The parsed json data

        Returns:
            list: A list of JSON records extracted via JSON path
        """
        # Handle jsonpath extraction of records
        LOGGER.debug('Parsing records with JSONPath: %s', self._json_path)

        result = jmespath.search(self._json_path, payload)
        if not result:
            return []

        if not isinstance(result, list):
            result = [result]

        return result

    def parse(self, data):
        """Main parser method to be handle parsing of the passed data

        Args:
            data (str|dict): Data to be parsed.

        Returns:
            bool: True if any records were parsed using this schema, False otherwise
        """
        # Ensure the schema is defined properly. Invalid schemas will not be used
        if not self._validate_schema():
            LOGGER.error('Schema definition is not valid (%s):\n%s', self._schema_type,
                         self._schema)
            return False

        data_copy = None
        # If the data is a mutable object, copy it since
        # the parse(s) can highly mutate the input
        if isinstance(data, dict):
            data_copy = deepcopy(data)

        # If the data is a string, attempt to load it to json,
        # falling back on a string type on error
        elif isinstance(data, (str, bytes)):
            try:
                data_copy = json.loads(data)
            except (ValueError, TypeError) as err:
                LOGGER.debug('Data is not valid json: %s', err)
                data_copy = data

        # Check to make sure any non-optional envelope keys exist before proceeding
        if not self._key_check(data_copy, self._envelope_schema, self._optional_envelope_keys,
                               True):
            return False

        # Get the envelope and try to convert the value to the proper type(s)
        envelope = self._extract_envelope(data_copy)
        if not self._convert_type(envelope, self._envelope_schema, self._optional_envelope_keys):
            return False

        # Add the optional envelope keys to record once at the beginning
        self._add_optional_keys(envelope, self._envelope_schema, self._optional_envelope_keys)

        for record, valid in self._parse(data_copy):
            valid = valid and self._key_check(record, self._schema, self._optional_top_level_keys)
            valid = valid and self._convert_type(record, self._schema,
                                                 self._optional_top_level_keys)
            valid = valid and self._matches_log_patterns(record, self._log_patterns, envelope)
            self._add_parse_result(record, valid, envelope)

        return self.valid

    @abstractmethod
    def _parse(self, data):
        """Protected parser method to be overridden by all Parser classes

        Args:
            data (str|dict): Data to be parsed.

        Returns:
            list<tuple>: List of tuples with records and their parsing status
                Examples: [({'key': 'value'}, True)]
        """


@parser
class JSONParser(ParserBase):
    """JSON record parser"""
    _type = 'json'
    _regex = re.compile(r'(?P<json_blob>{.+[:,].+}|\[.+[,:].+\])')

    @property
    def embedded_json(self):
        return self._configuration.get('embedded_json', False)

    @property
    def json_regex_key(self):
        return self._configuration.get('json_regex_key')

    def _extract_via_json_path(self, json_payload):
        """Extract records from the original json payload using the JSON configuration

        If the embedded_json flag is set, this will additionally attempt to load the
        extracted data as json into another dictionary object.

        Args:
            json_payload (dict): The parsed json data

        Returns:
            list: A list of one or more JSON records extracted via JSON path
        """
        extracted_records = self._json_path_records(json_payload)
        if not extracted_records:
            return False

        if not self.embedded_json:
            return [(rec, True) for rec in extracted_records]

        embedded_records = []
        for record in extracted_records:
            valid = True
            try:
                record = json.loads(record)
                if not isinstance(record, dict):
                    # purposely raising here to be caught below & handled
                    raise TypeError('record data is not a dictionary')
            except (ValueError, TypeError) as err:
                LOGGER.debug('Embedded json is invalid: %s', str(err))
                valid = False

            embedded_records.append((record, valid))

        return embedded_records

    def _extract_via_json_regex_key(self, json_payload):
        """Extract records from the original json payload using the JSON configuration

        Args:
            json_payload (dict): The parsed json data

        Returns:
            list: A list of JSON records extracted via JSON path or regex
        """
        # Handle nested json object regex matching
        if not json_payload.get(self.json_regex_key):
            return False

        LOGGER.debug('Parsing records with JSON Regex Key')
        match = self._regex.search(str(json_payload[self.json_regex_key]))
        if not match:
            return False

        match_str = match.groups('json_blob')[0]
        try:
            record = json.loads(match_str)
            if not isinstance(record, dict):
                # purposely raising here to be caught below & handled
                raise TypeError('record data is not a dictionary')
        except (ValueError, TypeError) as err:
            LOGGER.debug('Matched regex string is invalid (%s): %s', str(err), match_str)
            return False

        return [(record, True)]

    def _parse(self, data):
        """Identify and extract nested payloads from parsed JSON records.

        Nested payloads can be detected with 'json_path' or 'json_regex_key' option.
        The value of these should be a JMESpath (http://jmespath.org/) compliant search
        expression that returns the desired nested records.

        If desired, fields present on the root of the record can be merged into child
        events using the 'envelope_keys' option.

        Args:
            data (dict): The raw json data loaded as a dictionary

        Returns:
            list<tuple>: List of tuples with records and their parsing status
                Examples: [({'key': 'value'}, True)]
        """
        # TODO (ryandeivert): migrate all of this to the base class and do away with JSONParser
        if not (self._json_path or self.json_regex_key):
            return [(data, True)]  # Nothing special to be done

        records = []
        if self._json_path:
            records = self._extract_via_json_path(data)
        else:
            records = self._extract_via_json_regex_key(data)

        return records or [(data, False)]


@parser
class CSVParser(ParserBase):
    """CSV record parser"""
    _type = 'csv'

    @property
    def delimiter(self):
        # default delimiter = ','
        return str(self._configuration.get('delimiter', ','))

    @property
    def quotechar(self):
        # default quotechar = '"'
        return str(self._configuration.get('quotechar', '"'))

    @property
    def escapechar(self):
        # default escapechar = None
        # only cast to string if it exists since casting NoneType to string will result in 'None'
        return (str(self._configuration['escapechar'])
                if 'escapechar' in self._configuration else None)

    def _get_reader(self, data):
        """Return the CSV reader for the data using the configured delimiter, etc

        Returns:
            StringIO: Open CSV reader object or False upon error
        """
        try:
            if isinstance(data, bytes):
                data = data.decode()
            return csv.reader(io.StringIO(data),
                              delimiter=self.delimiter,
                              quotechar=self.quotechar,
                              escapechar=self.escapechar)
        except (ValueError, csv.Error):
            return False

    def _parse(self, data):
        """Parse a string into a comma separated value reader object

        Args:
            data (str): Data to be parsed.

        Returns:
            list<tuple>: List of tuples with records and their parsing status
                Examples: [({'key': 'value'}, True)]
        """
        extracted_data = []
        if self._json_path:
            # Support extraction of csv data within json
            extracted_data = self._json_path_records(data)
            if not extracted_data:
                return [(data, False)]

        # Fall back on the data as default if extraction failed
        data = extracted_data or [data]

        return self._extract_records(data, self._schema)

    def _extract_records(self, data, schema):
        """Extract record(s) from the csv data using the specified schema

        Args:
            data (list<str>): List of strings representing a csv row.
            schema (dict): Schema to be used for parsing.

        Returns:
            list<tuple>: List of tuples with records and their parsing status
                Examples: [({'key': 'value'}, True)]
        """
        csv_payloads = []
        for item in data:
            reader = self._get_reader(item)
            if not reader:
                csv_payloads.append((item, False))
                continue

            try:
                for row in reader:
                    parsed_payload = self._parse_row(row, schema)
                    result = parsed_payload or row
                    # Append the result and whether or not it was a success
                    csv_payloads.append((result, result is parsed_payload))
            except csv.Error:
                csv_payloads.append((item, False))

        return csv_payloads

    def _parse_row(self, row, schema):
        """Parse a single csv row using the specified schema

        Args:
            row (list): A list of strings representing a csv row
            schema (dict): Schema to be used for parsing

        Returns:
            dict: Parsed row with the corresponding schema
        """
        # check number of columns match
        if len(row) != len(schema):
            return False

        parsed_payload = {}
        for index, key in enumerate(schema):
            # if the value for this key in the schema is a dict, this must be a nested
            # value, so we should try to parse it as one and use the result
            if isinstance(schema[key], dict):
                parsed_data = self._extract_records([row[index]], schema[key])
                if parsed_data and parsed_data[0][1] is True:
                    parsed_payload[key] = parsed_data[0][0]
                    continue

                return False  # break the loop if the nested data was invalid

            # extract the keys from the row via the index
            parsed_payload[key] = row[index]

        return parsed_payload


@parser
class KVParser(ParserBase):
    """Key/value record parser"""
    _type = 'kv'

    @property
    def delimiter(self):
        # default delimiter = ' '
        return str(self._configuration.get('delimiter', ' '))

    @property
    def separator(self):
        # default separator = '='
        return str(self._configuration.get('separator', '='))

    def _parse(self, data):
        """Parse a key/value string into a dictionary

        Args:
            data (str): Data to be parsed

        Returns:
            list<tuple>: List of tuples with records and their parsing status
                Example: [({'key': 'value'}, True)]
        """
        record = self._extract_record(data)
        return [(record, True)] if record else [(data, False)]

    def _extract_record(self, data):
        """Extract the key/value record from the string of data

        Args:
            data (str): String of data from which to extract key/value information

        Returns:
            dict: Parsed keys and values from the string data, False upon failure
        """
        kv_payload = {}
        try:
            # remove any blank strings that may exist in our list
            fields = [field for field in data.split(self.delimiter) if field]
            # first check the field length matches our # of keys
            if len(fields) != len(self._schema):
                return False

            for index, field in enumerate(fields):
                # verify our fields contains the separator
                if self.separator not in field:
                    LOGGER.error('separator \'%s\' not found in field: %s', self.separator, field)
                    continue

                # only take data preceeding the first occurence of the field as the key
                key, value = field.split(self.separator, 1)
                # handle duplicate keys
                if key in kv_payload:
                    # load key from our configuration
                    kv_payload[list(self._schema.keys())[index]] = value
                else:
                    # add the data value
                    kv_payload[key] = value

        except UnicodeDecodeError:
            return False

        return kv_payload


@parser
class SyslogParser(ParserBase):
    """Syslog record parser"""
    _type = 'syslog'
    _regex = re.compile(r'(?P<timestamp>^\w{3}\s\d{2}\s(\d{2}:?)+)\s'
                        r'(?P<host>(\w[-]*)+)\s'
                        r'(?P<application>\w+)(\[\w+\])*:\s'
                        r'(?P<message>.*$)')

    def _parse(self, data):
        """Parse a syslog string into a dictionary

        Matches syslog events with the following format:
            timestamp(Month DD HH:MM:SS) host application: message
        Example(s):
            Jan 10 19:35:33 vagrant-ubuntu-trusty-64 sudo: session opened for root
            Jan 10 19:35:13 vagrant-ubuntu-precise-32 ssh[13941]: login for mike

        Args:
            data (str): Data to be parsed

        Returns:
            list<tuple>: List of tuples with records and their parsing status
                Examples: [({'key': 'value'}, True)]
        """
        match = self._regex.search(data)
        return [(match.groupdict(), True)] if match else [(data, False)]

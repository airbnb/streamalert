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
from abc import ABCMeta, abstractmethod
from collections import namedtuple
from copy import deepcopy
import csv
from fnmatch import fnmatch
import json
import logging
import re
import StringIO

import jmespath

from stream_alert.shared.logger import get_logger
from stream_alert.shared.stats import time_me


LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)
PARSERS = {}


# Simple ParseResult for storing the result of parsed records
ParseResult = namedtuple('ParseResult', ['record', 'valid'])


def parser(cls):
    """Class decorator to register parsers"""
    parser_type = cls.type()
    if not parser_type:
        raise NotImplementedError(
            '{}: Parser does not define a class property for \'_type\''.format(cls.__name__)
        )

    PARSERS[parser_type] = cls
    return cls


def get_parser(parserid):
    """Helper method to fetch parser classes

    Args:
        parserid (string): the name of the parser class to get

    Returns:
        A Parser class
    """
    return PARSERS[parserid]


class ParserBase:
    """Abstract Parser class to be inherited by all StreamAlert Parsers"""
    __metaclass__ = ABCMeta
    _type = None

    ENVELOPE_KEY = 'streamalert:envelope_keys'
    _TYPE_MAP = {
        'string': str,
        'integer': int,
        'float': float,
        'boolean': bool
    }

    def __init__(self, options):
        """Setup required parser properties

        Args:
            options (dict): Parser options - delimiter, separator, or log_patterns
        """
        self._options = options or {}
        self._valid_parses = []
        self._invalid_parses = []
        self._failed = False

    @classmethod
    def type(cls):
        """Returns the type of parser"""
        return cls._type

    @property
    def failed(self):
        return self._failed

    @property
    def schema(self):
        return self._options['schema']

    @property
    def configuration(self):
        return self._options.get('configuration', {})

    @property
    def optional_top_level_keys(self):
        return self.configuration.get('optional_top_level_keys')

    @property
    def log_patterns(self):
        return self.configuration.get('log_patterns')

    @property
    def json_path(self):
        return self.configuration.get('json_path')

    @property
    def envelope_schema(self):
        return self.configuration.get('envelope_keys', {})

    @property
    def optional_envelope_keys(self):
        return self.configuration.get('optional_envelope_keys')

    @property
    def valid(self):
        return len(self._valid_parses) != 0

    @property
    def invalid_parses(self):
        return self._invalid_parses

    @property
    def parses(self):
        return self._valid_parses

    def _add_parse_result(self, result, valid):
        if not valid:
            self._invalid_parses.append(result)
            return

        self._valid_parses.append(result)

    def _merge_schema_envelope(self):
        if self.envelope_schema and self.ENVELOPE_KEY not in self.schema:
            self.schema.update({self.ENVELOPE_KEY: self.envelope_schema})

    def _apply_envelope(self, envelope, record):
        if not envelope:
            return

        record.update({self.ENVELOPE_KEY: envelope})

    def _add_optional_keys(self, data, schema, optional_keys):
        """Add optional keys to a raw record

        Args:
            data (dict): JSONPath extracted JSON records
            schema (dict): The log type schema
            optional_keys (dict): The optional keys in the schema
        """
        if not (schema and optional_keys):
            return  # Nothing to do

        for key_name in optional_keys:
            # Instead of doing a schema.update() here with a default value type,
            # we should enforce having any optional keys declared within the schema
            # and log an error if that is not the case
            if key_name not in schema:
                LOGGER.error('Optional top level key \'%s\' '
                             'not found in declared log schema', key_name)
                continue

            # Add the optional key if it does not exist in the parsed json payload
            data[key_name] = data.get(key_name, self.default_optional_values(schema[key_name]))

    def _extract_envelope(self, json_payload):
        """Extract envelope key/values from the original payload

        Args:
            envelope_schema (dict): Envelope keys to be extracted
            json_payload (dict): The parsed json data

        Returns:
            dict: Key/values extracted from the log to be used as the envelope
        """
        if not self.envelope_schema:
            return

        if not isinstance(json_payload, dict):
            json_payload = json.loads(json_payload)

        LOGGER.debug('Extracting envelope keys')
        return {
            key: json_payload[key]
            for key in self.envelope_schema
        }

    def _extract_json_path(self, json_payload):
        """Extract records from the original json payload using a provided JSON path

        Args:
            json_payload (dict): The parsed json data

        Returns:
            list: A list of JSON records extracted via JSON path or regex
        """
        # If the csv parser is extracting csv from json, the payload is likely
        # a string and needs to be loaded to a dict
        if not isinstance(json_payload, dict):
            json_payload = json.loads(json_payload)

        # Handle jsonpath extraction of records
        LOGGER.debug('Parsing records with JSONPath')

        return jmespath.search(self.json_path, json_payload)

    def _convert_type(self, record, schema=None):
        """Convert a parsed payload's values into their declared types.

        If the schema is incorrectly defined for a particular field,
        this function will return False which will make the payload
        invalid.

        Args:
            payload (dict): Parsed payload dict
            schema (dict): data schema for a specific log source

        Returns:
            dict: parsed dict payload with typed values
        """
        schema = schema or self.schema

        for key, value in schema.iteritems():
            key = str(key)

            # Allow for null/NoneType values
            if record[key] is None:
                continue

            # if the schema value is declared as string
            if value == 'string':
                try:
                    record[key] = str(record[key])
                except UnicodeEncodeError:
                    record[key] = unicode(record[key])

            # if the schema value is declared as integer
            elif value == 'integer':
                try:
                    record[key] = int(record[key])
                except (ValueError, TypeError):
                    LOGGER.error('Invalid schema. Value for key [%s] is not an int: %s',
                                 key, record[key])
                    return False

            elif value == 'float':
                try:
                    record[key] = float(record[key])
                except (ValueError, TypeError):
                    LOGGER.error('Invalid schema. Value for key [%s] is not a float: %s',
                                 key, record[key])
                    return False

            elif value == 'boolean':
                record[key] = str(record[key]).lower() == 'true'

            elif isinstance(value, dict):
                if not value:
                    continue  # allow empty maps (dict)

                # Skip the values for the 'streamalert:envelope_keys' key that we've
                # added during parsing if the do not conform to being a dict
                if key == self.ENVELOPE_KEY and not isinstance(record[key], dict):
                    continue

                return self._convert_type(record[key], schema[key])

            elif isinstance(value, list):
                pass

            else:
                LOGGER.error('Unsupported schema type: %s', value)
                return False

        return True

    def matched_log_pattern(self, record, patterns=None):
        """Return True if all log patterns of this record match"""
        # Return True immediately if there are no log patterns
        # or if the data being tested is not a dict
        patterns = patterns or self.log_patterns
        if not patterns:
            return True

        pattern_result = []
        for field, pattern_list in patterns.iteritems():
            # handle nested log_patterns
            if isinstance(pattern_list, dict):
                return self.matched_log_pattern(record[field], pattern_list)

            if not isinstance(pattern_list, list):
                LOGGER.debug('Configured \'log_patterns\' should be a \'list\'')
                continue

            # The pattern field value in the record
            try:
                value = record[field]
            except (KeyError, TypeError):
                LOGGER.debug('Declared log pattern field [%s] is not a valid type '
                             'for this record: %s', field, record)
                continue
            # Append the result of any of the log_patterns being True
            pattern_result.append(any(fnmatch(value, pattern) for pattern in pattern_list))

        all_patterns_result = all(pattern_result)
        LOGGER.debug('%s log pattern match result: %s', self.type(), all_patterns_result)

        # if all pattern group results are True
        return all_patterns_result

    @classmethod
    def default_optional_values(cls, key):
        """Return a default value for a given schema type"""
        # Return instances of types that are defined, or of the type being passed in
        return cls._TYPE_MAP[key]() if isinstance(key, basestring) else type(key)()

    def parse(self, data):
        """Main parser method to be overridden by all Parser classes

        Args:
            data (str|dict): Data to be parsed.

        Yields:
            PayloadRecord: Represention of parsed records.
        """
        data_copy = None
        # If the data is a mutable object, copy it since
        # the parse(s) can highly mutate the input
        if isinstance(data, dict):
            data_copy = deepcopy(data)

        # If the data is a string, attempt to load it to json,
        # falling back on a string type on error
        elif isinstance(data, basestring):
            try:
                data_copy = json.loads(data_copy)
            except (ValueError, TypeError) as err:
                LOGGER.debug('Data is not valid json: %s', err.message)
                data_copy = data

        # Add optional envelope keys to the record, if defined - no-op otherwise
        self._add_optional_keys(data_copy, self.envelope_schema, self.optional_envelope_keys)

        # Note: no configuration essentially means data is by default valid
        # Also, ensure all of the required envelope keys exist if defined
        if not all(key in data_copy for key in self.envelope_schema):
            return False

        envelope = self._extract_envelope(data)

        for record, valid in self._parse(data_copy):
            valid = valid and self.matched_log_pattern(record)
            self._apply_envelope(envelope, record)
            self._add_parse_result(record, valid and self._convert_type(record))

        return self.valid

    @abstractmethod
    def _parse(self, data):
        """Protected parser method to be overridden by all Parser classes

        Args:
            data (str|dict): Data to be parsed.

        Yields:
            PayloadRecord: Represention of parsed records.
        """


@parser
class JSONParser(ParserBase):
    """JSON record parser."""
    _type = 'json'
    _regex = re.compile(r'(?P<json_blob>{.+[:,].+}|\[.+[,:].+\])')

    def __init__(self, *args, **kwargs):
        super(JSONParser, self).__init__(*args, **kwargs)
        self._merge_schema_envelope()

    @property
    def embedded_json(self):
        return self.configuration.get('embedded_json', False)

    @property
    def json_regex_key(self):
        return self.configuration.get('json_regex_key')

    def _key_check(self, json_record, schema=None):
        """Verify the declared schema matches the json payload

        Args:
            json_record (dict): A single dictionary representing a JSON payload

        Returns:
            bool: True if the log matches the schema, False if not
        """
        schema = schema or self.schema
        schema_keys = set(schema)

        json_keys = set(json_record)
        if json_keys != schema_keys:
            LOGGER.debug('Missing keys in record: %s', json_keys ^ schema_keys)
            return False

        match = True
        for key, key_type in schema.iteritems():
            # Skip the envelope key dictionary or any non dict sub type
            if key == self.ENVELOPE_KEY or not (key_type and isinstance(key_type, dict)):
                continue

            # Nested key check
            match = match and self._key_check(json_record[key], schema[key])

        if not match and LOGGER_DEBUG_ENABLED:
            LOGGER.debug('Schema: \n%s', json.dumps(schema, indent=2))
            LOGGER.debug('Key check failure: \n%s', json.dumps(json_record, indent=2))

        return match

    @time_me
    def _extract_records(self, json_raw_record):
        """Identify and extract nested payloads from parsed JSON records.

        Nested payloads can be detected with log_patterns (`records` should be a
        JSONpath selector that yields the desired nested records). If desired,
        fields present on the root record can be merged into child events
        using the `envelope_keys` option.

        Args:
            json_raw_record (dict): The raw json data loaded as a dictionary

        Returns:
            tuple: Records and their parsing status ie: (record, parsing_status)
        """
        if self.json_path:
            return self._extract_via_json_path(json_raw_record)

        if self.json_regex_key:
            return self._extract_via_json_regex_key(json_raw_record)

        return False

    def _extract_via_json_path(self, json_payload):
        """Extract records from the original json payload using the JSON configuration

        Args:
            json_payload (dict): The parsed json data

        Returns:
            list: A list of one or more JSON records extracted via JSON path or regex
        """
        extracted_records = self._extract_json_path(json_payload)
        if not extracted_records:
            return False

        if not self.embedded_json:
            return extracted_records

        embedded_records = []
        for record in extracted_records:
            valid = True
            try:
                record = json.loads(record)
                if not isinstance(record, dict):
                    # purposely raising here to be caught below & handled
                    raise TypeError('record data is not a dictionary')
            except (ValueError, TypeError) as err:
                LOGGER.debug('Embedded json is invalid: %s', err.message)
                valid = False

            embedded_records.append(record, valid)

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
            LOGGER.debug('Matched regex string is invalid (%s): %s', err.message, match_str)
            return False

        return [(record, True)]

    def _parse(self, data):
        """Parse a string into a list of JSON payloads.

        Args:
            data (str|dict): Data to be parsed

        Returns:
            list: A list of dictionaries representing parsed records OR
            False if the data is not JSON or the data does not follow the schema.
        """

        if valid and (self.json_path or self.json_regex_key):
            records = self._extract_records(data)
            valid = valid and bool(records)
            if valid:
                for record, valid in records:
                    if not valid:
                        print 'This was a failed parse of a sub record'  # TODO: remove me

                    self._add_optional_keys(record, self.schema, self.optional_top_level_keys)

                    # Yield the record and the result of key checking
                    yield record, valid and self._key_check(record)
                return

        # Just yield what we have if we get to this point
        yield data, valid


@parser
class CSVParser(ParserBase):
    """CSV record parser."""
    _type = 'csv'

    @property
    def delimiter(self):
        # default delimiter = ','
        return str(self.configuration.get('delimiter', ','))

    @property
    def quotechar(self):
        # default quotechar = '"'
        return str(self.configuration.get('quotechar', '"'))

    @property
    def escapechar(self):
        # default escapechar = None
        # only cast to string if it exists since casting NoneType to string will result in 'None'
        return (str(self.configuration['escapechar'])
                if 'escapechar' in self.configuration else None)

    def _get_reader(self, data):
        """Return the CSV reader for the given payload source

        Returns:
            StringIO: CSV reader object if the parse was successful OR
            False if parse was unsuccessful
        """
        try:
            return csv.reader(
                StringIO.StringIO(data),
                delimiter=self.delimiter,
                quotechar=self.quotechar,
                escapechar=self.escapechar
            )
        except (ValueError, csv.Error):
            return False

    def _parse(self, data):
        """Parse a string into a comma separated value reader object.

        Args:
            data (str): Data to be parsed.

        Returns:
            list: A list of dictionaries representing parsed records OR
            False if the data is not CSV or the columns do not match.
        """
        records = []
        if self.json_path:
            # Support extraction of csv data within json
            records = self._extract_json_path(data)
            if not records:
                self._failed = True
                return

        records = records or [data]

        return self._extract_records(records, self.schema)

    def _extract_records(self, records, schema):
        csv_payloads = []
        for item in records:
            reader = self._get_reader(item)
            if not reader:
                csv_payloads.append((item, False))
                continue

            try:
                for row in reader:
                    parsed_payload = self._parse_row(row, schema)
                    result = parsed_payload if parsed_payload else row
                    # Append the result and whether or not it was a success
                    csv_payloads.append((result, result is parsed_payload))
            except csv.Error:
                csv_payloads.append((item, False))
                return False

        return csv_payloads

    def _parse_row(self, row, schema):
        """Parse a single csv row and return the result

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
                parsed_data = self._extract_records(row[index], schema[key])
                if parsed_data and parsed_data[0][1] is True:
                    parsed_payload[key] = parsed_data[0][0]
                    continue

            # extract the keys from the row via the index
            parsed_payload[key] = row[index]

        return parsed_payload


@parser
class KVParser(ParserBase):
    """Parser for key-value type records."""
    _type = 'kv'

    @property
    def delimiter(self):
        # default delimiter = ' '
        return str(self.configuration.get('delimiter', ' '))

    @property
    def separator(self):
        # default separator = '='
        return str(self.configuration.get('separator', '"'))

    def _parse(self, data):
        """Parse a key value string into a dictionary.

        Args:
            data (str): Data to be parsed.

        Returns:
            list: A list of dictionaries representing parsed records OR
            False if the columns do not match.
        """
        record = self._extract_record(data)
        return [(record, True)] if record else [(data, False)]

    def _extract_record(self, data):

        kv_payload = {}
        try:
            # remove any blank strings that may exist in our list
            fields = [field for field in data.split(self.delimiter) if field]
            # first check the field length matches our # of keys
            if len(fields) != len(self.schema):
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
                    kv_payload[self.schema.keys()[index]] = value
                else:
                    # add the data value
                    kv_payload[key] = value

        except UnicodeDecodeError:
            return False

        return kv_payload


@parser
class SyslogParser(ParserBase):
    """Parser for syslog records."""
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
            list: A list of syslog records OR False if the data does not match the syslog regex.
        """
        match = self._regex.search(data)
        if not match:
            return [(data, False)]

        record = match.groupdict()

        return [(record, set(record) == set(self.schema))]

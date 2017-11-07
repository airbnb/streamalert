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
from collections import OrderedDict
import csv
from fnmatch import fnmatch
import json
import re
import StringIO

import jsonpath_rw

from stream_alert.rule_processor import LOGGER, LOGGER_DEBUG_ENABLED
from stream_alert.shared.stats import time_me

PARSERS = {}
ENVELOPE_KEY = 'streamalert:envelope_keys'

def parser(cls):
    """Class decorator to register parsers"""
    PARSERS[cls.__parserid__] = cls
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
    __parserid__ = ''

    def __init__(self, options):
        """Setup required parser properties

        Args:
            options (dict): Parser options - delimiter, separator, or log_patterns
        """
        self.options = options or {}

    @abstractmethod
    def parse(self, schema, data):
        """Main parser method to be overridden by all Parser classes

        Args:
            schema (dict): Parsing schema
            data (str|dict): Data to be parsed.

        Returns:
            list: Dictionaries representing parsed records.
        """

    def type(self):
        """Returns the type of parser. Overriden in GzipJSONParser to just return json"""
        return self.__parserid__

    def matched_log_pattern(self, record, log_patterns):
        """Return True if all log patterns of this record match"""
        # Return True immediately if there are no log patterns
        # or if the data being tested is not a dict
        if not log_patterns:
            return True

        pattern_result = []
        for field, pattern_list in log_patterns.iteritems():
            # handle nested log_patterns
            if isinstance(pattern_list, dict):
                return self.matched_log_pattern(record[field], pattern_list)

            if not isinstance(pattern_list, list):
                LOGGER.debug('Configured `log_patterns` should be a \'list\'')
                continue

            # The pattern field value in the record
            try:
                value = record[field]
            except (KeyError, TypeError):
                LOGGER.debug('Declared log pattern field [%s] is not a valid type '
                             'for this record: %s', field, record)
                continue
            # Append the result of any of the log_patterns being True
            pattern_result.append(any(fnmatch(value, pattern)
                                      for pattern in pattern_list))

        all_patterns_result = all(pattern_result)
        LOGGER.debug('%s log pattern match result: %s', self.type(), all_patterns_result)

        # if all pattern group results are True
        return all_patterns_result


@parser
class JSONParser(ParserBase):
    """JSON record parser."""
    __parserid__ = 'json'
    __regex = re.compile(r'(?P<json_blob>{.+[:,].+}|\[.+[,:].+\])')

    def _key_check(self, schema, json_records):
        """Verify the declared schema matches the json payload

        If keys do not match per the schema, records are removed from the
        passed in json_records list

        Args:
            json_records (list): List of dictionaries representing JSON payloads

        Returns:
            bool: True if any log in the list matches the schema, False if not
        """
        schema_keys = set(schema.keys())
        LOGGER.debug('Key checking %d records', len(json_records))

        # Because elements are deleted off of json_records during
        # iteration, this block uses a reverse range.
        for index in reversed(range(len(json_records))):
            schema_match = False
            json_keys = set(json_records[index].keys())
            if json_keys == schema_keys:
                schema_match = True
                for key, key_type in schema.iteritems():
                    if key == 'streamalert:envelope_keys' and isinstance(
                            json_records[index][key], dict):
                        continue
                    # Nested key check
                    if key_type and isinstance(key_type, dict):
                        schema_match = self._key_check(schema[key], [json_records[index][key]])

            if not schema_match:
                if LOGGER_DEBUG_ENABLED:
                    LOGGER.debug('Schema: \n%s', json.dumps(schema, indent=2))
                    LOGGER.debug(
                        'Key check failure: \n%s', json.dumps(json_records[index], indent=2))
                    LOGGER.debug(
                        'Missing keys in record: %s', json.dumps(list(json_keys ^ schema_keys)))
                del json_records[index]

        return bool(json_records)

    @staticmethod
    def _add_optional_keys(json_records, schema, optional_keys):
        """Add optional keys to a parsed JSON record.

        Args:
            json_records (list): JSONPath extracted JSON records
            schema (dict): The log type schema
            optional_keys (dict): The optional keys in the schema
        """
        if not optional_keys:
            return

        def _default_optional_values(key):
            """Return a default value for a given schema type"""
            if key == 'string':
                return str()
            elif key == 'integer':
                return int()
            elif key == 'float':
                return float()
            elif key == 'boolean':
                return bool()
            elif key == []:
                return list()
            elif key == OrderedDict():
                return dict()

        for key_name in optional_keys:
            # Instead of doing a schema.update() here with a default value type,
            # we should enforce having any optional keys declared within the schema
            # and log an error if that is not the case
            if key_name not in schema:
                LOGGER.error('Optional top level key \'%s\' '
                             'not found in declared log schema', key_name)
                continue
            # If the optional key isn't in our parsed json payload
            for record in json_records:
                if key_name not in record:
                    # Set default value
                    record[key_name] = _default_optional_values(schema[key_name])

    @time_me
    def _parse_records(self, schema, json_payload):
        """Identify and extract nested payloads from parsed JSON records.

        Nested payloads can be detected with log_patterns (`records` should be a
        JSONpath selector that yields the desired nested records). If desired,
        fields present on the root record can be merged into child events
        using the `envelope_keys` option.

        Args:
            json_payload (dict): The parsed json data

        Returns:
            list: A list of JSON recrods extracted via JSONPath.
        """
        # Check options and return the payload if there is nothing special to do
        if not self.options:
            return [json_payload]

        envelope_schema = self.options.get('envelope_keys')
        optional_envelope_keys = self.options.get('optional_envelope_keys')

        # If the schema has a defined envelope schema, with optional keys in
        # the envelope.  This occurs in some cases when using json_regex_key.
        if envelope_schema and optional_envelope_keys:
            missing_keys_schema = {}
            for key in optional_envelope_keys:
                if key not in json_payload:
                    missing_keys_schema[key] = envelope_schema[key]
            if missing_keys_schema:
                self._add_optional_keys([json_payload], envelope_schema, missing_keys_schema)

        # If the envelope schema is defined and all envelope keys are required
        # to be present in the record.
        elif envelope_schema and not all(x in json_payload for x in envelope_schema):
            return [json_payload]

        envelope = {}
        if envelope_schema:
            LOGGER.debug('Parsing envelope keys')
            schema.update({ENVELOPE_KEY: envelope_schema})
            envelope_keys = envelope_schema.keys()
            envelope_jsonpath = jsonpath_rw.parse("$." + ",".join(envelope_keys))
            envelope_matches = [match.value for match in envelope_jsonpath.find(json_payload)]
            envelope = dict(zip(envelope_keys, envelope_matches))

        json_records = []
        json_path_expression = self.options.get('json_path')
        # Handle jsonpath extraction of records
        if json_path_expression:
            LOGGER.debug('Parsing records with JSONPath')
            records_jsonpath = jsonpath_rw.parse(json_path_expression)
            matches = records_jsonpath.find(json_payload)
            if not matches:
                return False
            for match in matches:
                record = match.value
                if envelope:
                    record.update({ENVELOPE_KEY: envelope})
                json_records.append(record)

        # Handle nested json object regex matching
        json_regex_key = self.options.get('json_regex_key')
        if json_regex_key and json_payload.get(json_regex_key):
            LOGGER.debug('Parsing records with JSON Regex Key')
            match = self.__regex.search(str(json_payload[json_regex_key]))
            if not match:
                return False
            match_str = match.groups('json_blob')[0]
            try:
                new_record = json.loads(match_str)
            except ValueError:
                LOGGER.debug('Matched regex string is not valid JSON: %s', match_str)
                return False
            else:
                # Make sure the new_record is a dictionary and not a list.
                # Valid JSON can be either
                if not isinstance(new_record, dict):
                    return False
                if envelope:
                    new_record.update({ENVELOPE_KEY: envelope})

                json_records.append(new_record)

        # If the final parsed record is singular
        if not json_records:
            json_records.append(json_payload)

        return json_records

    @time_me
    def parse(self, schema, data):
        """Parse a string into a list of JSON payloads.

        Args:
            schema (dict): Parsing schema.
            data (str|dict): Data to be parsed.

        Returns:
            list: A list of dictionaries representing parsed records OR
            False if the data is not JSON or the data does not follow the schema.
        """
        if isinstance(data, (unicode, str)):
            try:
                loaded_data = json.loads(data)
            except ValueError as err:
                LOGGER.debug('JSON parse failed: %s', str(err))
                LOGGER.debug('JSON parse could not load data: %s', str(data))
                return False
            else:
                json_records = self._parse_records(schema, loaded_data)
        else:
            json_records = self._parse_records(schema, data)

        if not json_records:
            return False

        self._add_optional_keys(json_records,
                                schema,
                                self.options.get('optional_top_level_keys'))
        # Make sure all keys match the schema, including nests maps
        if not self._key_check(schema, json_records):
            return False

        return json_records


@parser
class CSVParser(ParserBase):
    """CSV record parser."""
    __parserid__ = 'csv'
    __default_delimiter = ','

    def _get_reader(self, data):
        """Return the CSV reader for the given payload source

        Returns:
            StringIO: CSV reader object if the parse was successful OR
            False if parse was unsuccessful
        """
        delimiter = self.options.get('delimiter', self.__default_delimiter)

        # TODO(ryandeivert): either subclass a current parser or add a new
        # parser to support parsing CSV data that contains a header line
        try:
            csv_data = StringIO.StringIO(data)
            reader = csv.reader(csv_data, delimiter=delimiter)
        except (ValueError, csv.Error):
            return False

        return reader

    def parse(self, schema, data):
        """Parse a string into a comma separated value reader object.

        Args:
            schema (dict): Parsing schema.
            data (str): Data to be parsed.

        Returns:
            list: A list of dictionaries representing parsed records OR
            False if the data is not CSV or the columns do not match.
        """
        reader = self._get_reader(data)
        if not reader:
            return False

        csv_payloads = []
        try:
            for row in reader:
                # check number of columns match
                if len(row) != len(schema):
                    return False

                parsed_payload = {}
                for index, key in enumerate(schema):
                    # extract the keys from the row via the index
                    parsed_payload[key] = row[index]

                    # if the value for this key in the schema is a dict, this must be a nested
                    # value, so we should try to parse it as one and replace the value
                    if isinstance(schema[key], dict):
                        parsed_data = self.parse(schema[key], row[index])
                        if parsed_data:
                            parsed_payload[key] = parsed_data[0]

                csv_payloads.append(parsed_payload)

            return csv_payloads
        except csv.Error:
            return False


@parser
class KVParser(ParserBase):
    """Parser for key-value type records."""
    __parserid__ = 'kv'
    __default_separator = '='
    __default_delimiter = ' '

    def parse(self, schema, data):
        """Parse a key value string into a dictionary.

        Args:
            schema (dict): Parsing schema.
            data (str): Data to be parsed.

        Returns:
            list: A list of dictionaries representing parsed records OR
            False if the columns do not match.
        """
        # get the delimiter (character between key/value pairs) and the
        # separator (the character between keys and values)
        delimiter = self.options.get('delimiter', self.__default_delimiter)
        separator = self.options.get('separator', self.__default_separator)

        kv_payload = {}
        try:
            # remove any blank strings that may exist in our list
            fields = [field for field in data.split(delimiter) if field]
            # first check the field length matches our # of keys
            if len(fields) != len(schema):
                return False

            regex = re.compile('.+{}.+'.format(separator))
            for index, field in enumerate(fields):
                # verify our fields match the kv regex
                if regex.match(field):
                    key, value = field.split(separator)
                    # handle duplicate keys
                    if key in kv_payload:
                        # load key from our configuration
                        kv_payload[schema.keys()[index]] = value
                    else:
                        # load key from data
                        kv_payload[key] = value
                else:
                    LOGGER.error('key/value regex failure for %s', field)

            return [kv_payload]
        except UnicodeDecodeError:
            return False


@parser
class SyslogParser(ParserBase):
    """Parser for syslog records."""
    __parserid__ = 'syslog'
    __regex = re.compile(r"(?P<timestamp>^\w{3}\s\d{2}\s(\d{2}:?)+)\s"
                         r"(?P<host>(\w[-]*)+)\s"
                         r"(?P<application>\w+)(\[\w+\])*:\s"
                         r"(?P<message>.*$)")

    def parse(self, schema, data):
        """Parse a syslog string into a dictionary

        Matches syslog events with the following format:
            timestamp(Month DD HH:MM:SS) host application: message
        Example(s):
            Jan 10 19:35:33 vagrant-ubuntu-trusty-64 sudo: session opened for root
            Jan 10 19:35:13 vagrant-ubuntu-precise-32 ssh[13941]: login for mike

        Args:
            schema (dict): Syslog schema
            data (str): Data to be parsed

        Returns:
            list: A list of syslog records OR False if the data does not match the syslog regex.
        """
        match = self.__regex.search(data)
        if not match:
            return False

        return [{key: match.group(key) for key in schema.keys()}]

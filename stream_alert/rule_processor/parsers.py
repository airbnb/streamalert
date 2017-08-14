'''
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
'''
import csv
import json
import re
import StringIO

from abc import ABCMeta, abstractmethod
from collections import OrderedDict
from fnmatch import fnmatch

import jsonpath_rw

from stream_alert.rule_processor import LOGGER

PARSERS = {}


def parser(cls):
    """Class decorator to register parsers"""
    PARSERS[cls.__parserid__] = cls
    return cls


def get_parser(parserid):
    """Helper method to fetch parser classes

    Args:
        parserid: the name of the parser class to get

    Returns:
        - A Parser class
    """
    return PARSERS[parserid]


class ParserBase:
    """Abstract Parser class to be inherited by all StreamAlert Parsers"""
    __metaclass__ = ABCMeta
    __parserid__ = ''

    def __init__(self, options):
        """Setup required parser properties

        Args:
            schema: Dict of log data schema.
            options: Parser options dict - delimiter, separator, or log_patterns
        """
        self.options = options or {}

    @abstractmethod
    def parse(self, schema, data):
        """Main parser method to be overridden by all Parser classes

        Args:
            data [str or dict]: Data to be parsed.

        Returns:
            [list] A list of dictionaries representing parsed records.
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
        # if not all_patterns_result:
            # LOGGER.debug('Failed Log Pattern Match: %s', json.dumps(record, indent=4))

        # if all pattern group results are True
        return all(pattern_result)


@parser
class JSONParser(ParserBase):
    __parserid__ = 'json'

    def _key_check(self, schema, json_records):
        """Verify the declared schema matches the json payload

        If keys do not match per the schema, records are removed from the
        passed in json_records list

        Args:
            json_records [list]: List of dictionaries representing JSON payloads

        Returns:
            [bool] True if any log in the list matches the schema, False if not
        """
        schema_keys = set(schema.keys())
        schema_match = False

        for index in reversed(range(len(json_records))):
            json_keys = set(json_records[index].keys())
            if json_keys == schema_keys:
                schema_match = True
                for key, key_type in schema.iteritems():
                    if key == 'streamalert:envelope_keys' and isinstance(json_records[index][key], dict):
                        continue
                    # Nested key check
                    if key_type and isinstance(key_type, dict):
                        schema_match = self._key_check(schema[key], [json_records[index][key]])

            if not schema_match:
                LOGGER.debug('Schema: \n%s', json.dumps(schema, indent=4))
                LOGGER.debug('Key Check Failure: \n%s', json.dumps(json_records[index], indent=4))
                LOGGER.debug('Missing Keys in Record: %s', json.dumps(list(json_keys - schema_keys)))
                del json_records[index]

        return bool(json_records)

    def _parse_records(self, schema, json_payload):
        """Iterate over a json_payload. Identify and extract nested payloads.
        Nested payloads can be detected with log_patterns (`records` should be a
        JSONpath selector that yields the desired nested records).

        If desired, fields present on the root record can be merged into child
        events using the `envelope_keys` option.

        Args:
            json_payload [dict]: The parsed json data

        Returns:
            [list] A list of dictionaries representing parsed records.
        """
        # Check options and return the payload if there is nothing special to do
        if not self.options:
            return [json_payload]

        envelope_schema = self.options.get('envelope_keys')
        # If envelope_keys are declared, and this payload does not have every key specified
        # in these envelope_keys, then it's safe to skip trying to extract records using json_path
        if envelope_schema and not all(x in json_payload for x in envelope_schema):
            return [json_payload]

        json_records = []
        records_schema = self.options.get('json_path')
        # Handle jsonpath extraction of records
        if records_schema:
            envelope = {}
            if envelope_schema:
                schema.update({'streamalert:envelope_keys': envelope_schema})
                envelope_keys = envelope_schema.keys()
                envelope_jsonpath = jsonpath_rw.parse("$." + ",".join(envelope_keys))
                envelope_matches = [match.value for match in envelope_jsonpath.find(json_payload)]
                envelope = dict(zip(envelope_keys, envelope_matches))

            records_jsonpath = jsonpath_rw.parse(records_schema)
            for match in records_jsonpath.find(json_payload):
                record = match.value
                if envelope:
                    record.update({'streamalert:envelope_keys': envelope})

                json_records.append(record)

        if not json_records:
            json_records.append(json_payload)

        optional_keys = self.options.get('optional_top_level_keys')
        # Handle optional keys
        if optional_keys:

            def default_optional_values(key):
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
                        record[key_name] = default_optional_values(schema[key_name])

        return json_records

    def parse(self, schema, data):
        """Parse a string into a list of JSON payloads.

        Args:
            data [str or dict]: Data to be parsed.

        Returns:
            [list] A list of dictionaries representing parsed records.
            [boolean] False if the data is not JSON or the data does not follow the schema.
        """
        if isinstance(data, (unicode, str)):
            try:
                data = json.loads(data)
            except ValueError as err:
                LOGGER.debug('JSON parse failed: %s', str(err))
                return False

        json_records = self._parse_records(schema, data)
        # Make sure all keys match the schema, including nests maps
        if not self._key_check(schema, json_records):
            return False

        return json_records


@parser
class CSVParser(ParserBase):
    __parserid__ = 'csv'
    __default_delimiter = ','

    def _get_reader(self, data):
        """Return the CSV reader for the given payload source

        Returns:
            [StringIO] CSV reader object if the parse was successful
            [boolean] False if parse was unsuccessful
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
            data [str]: Data to be parsed.

        Returns:
            [list] A list of dictionaries representing parsed records.
            [boolean] False if the data is not CSV or the columns do not match.
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
    __parserid__ = 'kv'
    __default_separator = '='
    __default_delimiter = ' '

    def parse(self, schema, data):
        """Parse a key value string into a dictionary.

        Args:
            data [str]: Data to be parsed.

        Returns:
            [list] A list of dictionaries representing parsed records.
            [boolean] False if the columns do not match.
        """
        # get the delimiter (character between key/value pairs) and the
        # separator (the character between keys and values)
        delimiter = self.options.get('delimiter', self.__default_delimiter)
        separator = self.options.get('separator', self.__default_separator)

        kv_payload = {}
        try:
            # remove any blank strings that may exist in our list
            fields = filter(None, data.split(delimiter))
            # first check the field length matches our # of keys
            if len(fields) != len(schema):
                LOGGER.debug('KV field length mismatch: %s vs %s', fields, schema)
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
    __parserid__ = 'syslog'

    def parse(self, schema, data):
        """Parse a syslog string into a dictionary

        Matches syslog events with the following format:
            timestamp(Month DD HH:MM:SS) host application: message
        Example(s):
            Jan 10 19:35:33 vagrant-ubuntu-trusty-64 sudo: session opened for root
            Jan 10 19:35:13 vagrant-ubuntu-precise-32 ssh[13941]: login for mike

        Args:
            data: Data to be parsed

        Returns:
            [list] A list of syslog records.
            [boolean] False if the data does not match the syslog regex.
        """
        syslog_regex = re.compile(r"(?P<timestamp>^\w{3}\s\d{2}\s(\d{2}:?)+)\s"
                                  r"(?P<host>(\w[-]*)+)\s"
                                  r"(?P<application>\w+)(\[\w+\])*:\s"
                                  r"(?P<message>.*$)")

        match = syslog_regex.search(data)
        if not match:
            return False

        return [{key: match.group(key) for key in schema.keys()}]

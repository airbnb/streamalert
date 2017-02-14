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
import logging
import re
import StringIO

from abc import ABCMeta, abstractmethod
from fnmatch import fnmatch

logging.basicConfig()
logger = logging.getLogger('StreamAlert')

def get_parser(parserid):
    """Helper method to fetch parser classes

    Args:
        parserid: the name of the parser class to get

    Returns:
        - A Parser class
    """
    return PARSERS[parserid]

PARSERS = {}
def parser(cls):
    """Class decorator to register parsers"""
    PARSERS[cls.__parserid__] = cls
    return cls

class ParserBase:
    """Abstract Parser class to be inherited by all StreamAlert Parsers"""
    __metaclass__ = ABCMeta

    def __init__(self, data, schema, options):
        """Setup required parser properties

        Args:
            data: Data string to be parsed.
            schema: Dict of log data schema.
            options: Parser options dict - delimiter, separator, or hints
        """
        self.data = data
        self.schema = schema
        self.options = options
        # If we can parse into a correct type, but keys or other config
        # options do not match up, we can set a type in the payload object
        # to short circuit type determination.
        self.payload_type = None

    @abstractmethod
    def parse(self):
        """Main parser method to be overridden by all Parser classes"""
        pass

@parser
class JSONParser(ParserBase):
    __parserid__ = 'json'

    def parse(self):
        """Parse a string into JSON.

        Options:
            - None

        Returns:
            - A dict of the parsed JSON record.
            - False if the data is not JSON or the columns do not match.
        """
        schema = self.schema
        data = self.data

        try:
            json_payload = json.loads(data)
            self.payload_type = 'json'
        except ValueError:
            return False

        # top level key check
        json_keys = set(json_payload.keys())
        schema_keys = set(schema.keys())
        if json_keys == schema_keys:
            # subkey check
            for key, key_type in schema.iteritems():
                # if the key is a map of key/value pairs
                if isinstance(key_type, dict) and key_type != {}:
                    if set(json_payload[key].keys()) != set(schema[key].keys()):
                        return False
            return json_payload
        else:
            logger.debug('JSON Key mismatch: %s vs. %s', json_keys, schema_keys)
            return False

@parser
class CSVParser(ParserBase):
    __parserid__ = 'csv'
    __default_delimiter = ','

    def _get_reader(self):
        """Return the CSV reader for the given payload source

        Returns:
            - CSV reader object if the parse was successful
            - False if parse was unsuccessful
        """
        data = self.data
        service = self.options['service']
        delimiter = self.options['delimiter'] or self.__default_delimiter

        if service == 's3':
            try:
                csv_data = StringIO.StringIO(data)
                reader = csv.DictReader(csv_data, delimiter=delimiter)
            except ValueError:
                return False

        elif service == 'kinesis':
            try:
                csv_data = StringIO.StringIO(data)
                reader = csv.reader(csv_data, delimiter=delimiter)
            except ValueError:
                return False

        return reader

    def parse(self):
        """Parse a string into a comma separated value reader object.

        Options:
            - hints: A dict of string wildcards to find in payload fields.

        Returns:
            - A dict of the parsed CSV record.
            - False if the data is not CSV or the columns do not match.
        """
        schema = self.schema
        hints = self.options['hints']

        hint_result = []
        csv_payload = {}

        reader = self._get_reader()
        if not reader:
            return False

        for row in reader:
            # check number of columns match and any hints match
            if len(row) != len(schema):
                logger.debug('CSV Key mismatch: %s vs. %s', len(row), len(schema))
                return False

            for field, hint_list in hints.iteritems():
                # handle nested hints
                if not isinstance(hint_list, list):
                    continue
                # the hint field index in the row
                field_index = schema.keys().index(field)
                # store results per hint
                hint_group_result = []
                for hint in hint_list:
                    hint_group_result.append(fnmatch(row[field_index], hint))
                # append the result of any of the hints being True
                hint_result.append(any(hint_group_result))

            # if all hint group results are True
            logger.debug('hint result: %s', hint_result)
            if all(hint_result):
                self.payload_type = 'csv'
                for index, key in enumerate(schema):
                    csv_payload[key] = row[index]

                return csv_payload

@parser
class KVParser(ParserBase):
    __parserid__ = 'kv'
    __default_separator = '='
    __default_delimiter = ' '

    def parse(self):
        """Parse a key value string into a dictionary.

        Options:
            - delimiter: The character between key/value pairs.
            - separator: The character between keys and values.

        Returns:
            - A dict of the loaded key value pairs.
            - False if the columns do not match.
        """
        data = self.data
        schema = self.schema
        options = self.options

        delimiter = options['delimiter'] or self.__default_delimiter
        separator = options['separator'] or self.__default_separator

        kv_payload = {}

        # remove any blank strings that may exist in our list
        fields = filter(None, data.split(delimiter))
        # first check the field length matches our # of keys
        if len(fields) != len(schema):
            logger.debug('Parsed KV fields: %s', fields)
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
                logger.error('key/value regex failure for %s', field)

        self.payload_type = 'kv'

        return kv_payload

@parser
class SyslogParser(ParserBase):
    __parserid__ = 'syslog'

    def parse(self):
        """Parse a syslog string into a dictionary

        Matches syslog events with the following format:
            timestamp(Month DD HH:MM:SS) host application: message
        Example(s):
            Jan 10 19:35:33 vagrant-ubuntu-trusty-64 sudo: session opened for root
            Jan 10 19:35:13 vagrant-ubuntu-precise-32 ssh[13941]: login for mike

        Options:
            - None

        Returns:
            - A dict of syslog key-value pairs.
            - False if the data does not match the syslog regex.
        """
        schema = self.schema
        data = self.data

        syslog_payload = {}
        syslog_regex = re.compile(r"(?P<timestamp>^\w{3}\s\d{2}\s(\d{2}:?)+)\s"
                                  r"(?P<host>(\w[-]*)+)\s"
                                  r"(?P<application>\w+)(\[\w+\])*:\s"
                                  r"(?P<message>.*$)")

        match = syslog_regex.search(data)
        if not match:
            return False

        self.payload_type = 'syslog'
        for key in schema.keys():
            syslog_payload[key] = match.group(key)

        return syslog_payload

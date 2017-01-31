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

import base64
import csv
import gzip
import json
import logging
import os
import re
import StringIO
import tempfile
import time
import urllib

from collections import OrderedDict
from fnmatch import fnmatch

import boto3

logging.basicConfig()
logger = logging.getLogger('StreamAlert')

class S3ObjectSizeError(Exception):
    pass

class InvalidSchemaError(Exception):
    pass

class StreamPayload(object):
    """Classify and parse a raw record into its declared type.

    Attributes:
        valid: A boolean representing if the record is deemed valid by
            parsing and classification logic.

        service: The aws service where the record originated from. Can be
            either S3 or kinesis.

        entity: The instance of the sending service. Can be either a
            specific kinesis stream or S3 bucket name.

        log_source: The name of the logging application which the data
            originated from.  This could be osquery, auditd, etc.

        type: The data type of the record - json, csv, syslog, or kv.

        record: A typed record.

        s3_file: A full path to a downloaded file from S3.

    Public Methods:
        classify_record
        parse_json
        parse_csv
        parse_syslog
    """

    def __init__(self, **kwargs):
        """
        Keyword Args:
            env (dict): Loaded environment data about the currently running lambda
            raw_record (dict): The record to be parsed
            log_metadata (dict): Log sources and their attributes for the entity
            config (dict): Loaded JSON configuration files.  Contains two keys:
                logs, and sources
        """
        self.valid = False
        self.service = None
        self.entity = None
        self.type = None
        self.log_source = None
        self.record = None

        self.log_metadata = kwargs.get('log_metadata', None)
        self.raw_record = kwargs.get('raw_record')
        self.env = kwargs.get('env')
        self.config = kwargs.get('config')

    def __repr__(self):
        return '<StreamPayload valid:{} log_source:{} entity:{} type:{} record:{} >'.format(
            self.valid, self.log_source, self.entity, self.type, self.record)

    def refresh_record(self, new_record):
        """Replace the currently loaded record with a new one.

        Used mainly when S3 is used as a source, due to looping over files
        downloadd from S3 events verses all records being readily available
        from a Kinesis stream.

        Args:
            new_record (str): A new raw record to be parsed
        """
        self.raw_record = None
        self.record = None
        self.valid = None
        self.type = None
        self.raw_record = new_record

    def map_source(self):
        """Map a record to its originating AWS service and entity.

        Each raw record contains a set of keys to represent its source.
        A Kinesis record will contain a `kinesis` key while a
        S3 record contains `s3`.

        Sets:
            self.service: The AWS service which sent the record
            self.entity: The specific instance of a service which sent the record
            self.log_metadata: All logs for a declared entity, with their attrs.
        """
        # check raw record for either kinesis or s3 keys
        if 'kinesis' in self.raw_record:
            self.service = 'kinesis'
        elif 's3' in self.raw_record:
            self.service = 's3'

        # map the entity name from a record
        entity_mapper = {
            'kinesis': lambda r: r['eventSourceARN'].split('/')[1],
            's3': lambda r: r['s3']['bucket']['name']
        }
        # get the entity name
        self.entity = entity_mapper[self.service](self.raw_record)

        # get all entities for the configured service (s3 or kinesis)
        all_service_entities = self.config['sources'][self.service]
        config_entity = all_service_entities.get(self.entity)

        if config_entity:
            entity_log_sources = config_entity['logs']
            self.log_metadata = self._log_metadata(entity_log_sources, self.config.get('logs'))

    @staticmethod
    def _log_metadata(entity_log_sources, all_config_logs):
        """Return a mapping of all log sources to a given entity with attributes.

        Args:
            entity_log_sources (list): All log sources declared for a source entity.
            all_config_logs (dict): JSON loaded conf/logs.conf file.

        Returns:
            (dict) log sources and their attributes for the entity:
            {
                'log_source_1': {
                    'parser': 'json',
                    'keys': [ 'key1', 'key2', ..., 'keyn']
                },
                'log_source_n': {
                    'parser': 'csv',
                    'keys': ['field1', 'field2', ..., 'fieldn'],
                    'hints': ['*hint1*']
                }
            }
        """
        metadata = {}
        for log_source, log_source_attributes in all_config_logs.iteritems():
            source_pieces = log_source.split(':')
            category = source_pieces[0]
            if category in entity_log_sources:
                metadata[log_source] = log_source_attributes
        return metadata

    def classify_record(self, data):
        """Classify and type raw record passed into StreamAlert.

        Before we apply our rules to a record passed to the lambda function,
        we need to validate a record.  Validation requires verifying its source,
        checking that we have declared it in our configuration, and indeitifying
        the record's data source and parsing its data type.

        Args:
            data (str): a raw record to classify
        """
        if self.log_metadata:
            parse_result = self._parse(data)
            if all([
                    parse_result,
                    self.service,
                    self.entity,
                    self.type,
                    self.log_source,
                    self.record
            ]):
                self.valid = True

    def _parse(self, data):
        """Parse a record into a declared type.

        Args:
            data (str): A decoded data string from the event record.

        Sets:
            self.log_source: The detected log name from the data_sources config.
            self.type: The record's type.
            self.record: The parsed record.

        Returns:
            A boolean representing the success of the parse.
        """
        for log_name, attributes in self.log_metadata.iteritems():
            if not self.type:
                parser = attributes.get('parser')
            else:
                parser = self.type
            parser_method = getattr(self, 'parse_{}'.format(parser))

            args = {}
            args['schema'] = attributes.get('schema')
            args['hints'] = attributes.get('hints')
            args['parser'] = parser
            args['delimiter'] = attributes.get('delimiter')
            args['separator'] = attributes.get('separator')

            parsed_data = parser_method(data, args)
            logger.debug('log_name: %s', log_name)
            logger.debug('parsed_data: %s', parsed_data)

            if parsed_data:
                parsed_and_typed_data = self._convert_type(parsed_data, args)
                if parsed_and_typed_data:
                    self.log_source = log_name
                    self.type = parser
                    self.record = parsed_data
                    return True
        return False

    def _convert_type(self, payload, args):
        """Convert a parsed payload's values into their declared types.

        If the schema is incorrectly defined for a particular field,
        this function will return False which will make the payload
        invalid.

        Args:
            payload (dict): parsed payload object
            args (dict): log type schema denoting keys with their value types

        Returns:
            (dict) parsed payload with typed values
        """
        schema = args['schema']
        for key, value in schema.iteritems():
            key = str(key)
            # if the schema value is declared as string
            if value == 'string':
                payload[key] = str(payload[key])

            # if the schema value is declared as integer
            elif value == 'integer':
                try:
                    payload[key] = int(payload[key])
                except ValueError as e:
                    logger.error('Invalid schema - %s is not an int', key)
                    return False

            elif isinstance(value, (OrderedDict)):
                if len(value) == 0:
                    pass
                else:
                    args['schema'] = schema[key]
                    # handle nested csv
                    if isinstance(payload[key], str):
                        args['hints'] = args['hints'][key]
                        payload[key] = self.parse_csv(payload[key], args)
                    self._convert_type(payload[key], args)
            else:
                logger.error('Invalid declared type - %s', value)

        return payload

    def parse_json(self, data, args):
        """Parse a string into JSON.

        Args:
            data (str): A decoded data string from a Lambda event.
            args (dict): All parser arguments, JSON uses:
                schema: Log type structure, including keys and their type.

        Returns:
            A dictionary representing the data passed in.
            False if the data is not JSON or the keys do not match.
        """
        schema = args['schema']
        try:
            json_payload = json.loads(data)
            self.type = 'json'
        except ValueError:
            return False

        # top level key check
        if set(json_payload.keys()) == set(schema.keys()):
            # subkey check
            for key, key_type in schema.iteritems():
                # if the key is a map of key/value pairs
                if isinstance(key_type, dict) and key_type != {}:
                    if set(json_payload[key].keys()) != set(schema[key].keys()):
                        return False
            return json_payload
        else:
            # logger.debug('JSON Key mismatch: %s vs. %s', json_payload.keys(), args['keys'])
            return False

    def parse_csv(self, data, args):
        """Parse a string into a comma separated value reader object.

        Args:
            data (str): A decoded data string from a Lambda event.
            args (dict): All parser arguments, CSV uses:
                schema: Log type structure, including keys and their type.
                hints: A list of string wildcards to find in data.

        Returns:
            A dict of the parsed CSV record
        """
        schema = args['schema']
        hints = args['hints']
        hint_result = []
        csv_payload = {}

        if self.service == 's3':
            try:
                csv_data = StringIO.StringIO(data)
                reader = csv.DictReader(csv_data, delimiter=',')
            except ValueError:
                return False

        elif self.service == 'kinesis':
            try:
                csv_data = StringIO.StringIO(data)
                reader = csv.reader(csv_data, delimiter=',')
            except ValueError:
                return False

        if reader and hints:
            for row in reader:
                # check number of columns match and any hints match
                logger.debug('hint result: %s', hint_result)
                if len(row) == len(schema):
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
                    if all(hint_result):
                        self.type = 'csv'
                        for index, key in enumerate(schema):
                            csv_payload[key] = row[index]
                        return csv_payload
                else:
                    # logger.debug('CSV Key mismatch: %s vs. %s', len(row), len(schema))
                    return False
        else:
            return False

    def parse_kv(self, data, args):
        """Parse a key value string into a dictionary.

        Args:
            data (str): A decoded data string from a Lambda event.
            args (dict): All parser arguments, KV uses:
                schema: Log type structure, including keys and their type.
                delimiter: The character between key/value pairs.
                separator: The character between keys and values.

        Returns:
            (dict) of the loaded key value pairs
        """
        delimiter = args['delimiter']
        separator = args['separator']
        schema = args['schema']
        kv_payload = {}

        # remove any blank strings that may exist in our list
        fields = filter(None, data.split(delimiter))
        # first check the field length matches our # of keys
        if len(fields) == len(schema):
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
            self.type = 'kv'
            return kv_payload
        else:
            return False

    def parse_syslog(self, data, args):
        """Parse a syslog string into a dictionary

        Matches syslog events with the following format:
            timestamp(Month DD HH:MM:SS) host application: message
        Example(s):
            Jan 10 19:35:33 vagrant-ubuntu-trusty-64 sudo: session opened for root
            Jan 10 19:35:13 vagrant-ubuntu-precise-32 ssh[13941]: login for mike

        Args:
            data (str): A decoded data string from a Lambda event.
            args (dict): All parser arguments, Syslog uses:
                schema: Log type structure, including keys and their type.

        Returns:
            (dict) syslog key-value pairs
        """
        schema = args['schema']
        syslog_payload = {}
        syslog_regex = re.compile(r"(?P<timestamp>^\w{3}\s\d{2}\s(\d{2}:?)+)\s"
                                  r"(?P<host>(\w[-]*)+)\s"
                                  r"(?P<application>\w+)(\[\w+\])*:\s"
                                  r"(?P<message>.*$)")

        match = syslog_regex.search(data)
        if match:
            for key in schema.keys():
                syslog_payload[key] = match.group(key)
            self.type = 'syslog'
            return syslog_payload
        else:
            return False

class StreamPayloadHelpers(object):
    """Helper functions to parse incoming data into a string for classificaiton"""
    @classmethod
    def pre_parse_kinesis(cls, raw_record):
        """Decode a Kinesis record.

        Args:
            raw_record (dict): A Kinesis event record.

        Returns: (string) Base64 decoded data.
        """
        return base64.b64decode(raw_record['kinesis']['data'])

    @classmethod
    def _download_s3_object(cls, client, bucket, key, size):
        """Download an object from S3.

        Verifies the S3 object is less than or equal to 128MB, and
        stores into a temp file.  Lambda can only execute for a
        maximum of 300 seconds, and the file to download
        greatly impacts that time.

        Args:
            client: boto3 s3 client object
            bucket (string): s3 bucket to download object from
            key (string): key of s3 object
            size (int): size of s3 object in bytes

        Returns:
            (string) The downloaded path of the S3 object.
        """
        size_kb = size / 1024
        size_mb = size_kb / 1024
        if size_mb > 128:
            raise S3ObjectSizeError('S3 object to download is above 500MB')

        logger.debug('/tmp directory contents:%s ', os.listdir('/tmp'))
        logger.debug(os.system('df -h /tmp | tail -1'))

        if size_mb:
            display_size = '{}MB'.format(size_mb)
        else:
            display_size = '{}KB'.format(size_kb)
        logger.info('Starting download from S3 - %s/%s [%s]',
                    bucket, key, display_size)

        suffix = key.replace('/', '-')
        _, downloaded_s3_object = tempfile.mkstemp(suffix=suffix)
        with open(downloaded_s3_object, 'wb') as data:
            start_time = time.time()
            client.download_fileobj(bucket, key, data)

        end_time = time.time() - start_time
        logger.info('Completed download in %s seconds', round(end_time, 2))

        return downloaded_s3_object

    @classmethod
    def _read_s3_file(cls, downloaded_s3_object):
        """Parse a downloaded file from S3

        Supports reading both gzipped files and plaintext files. Truncates
        files after reading to save space on /tmp mount.

        Args:
            downloaded_s3_object (string): A full path to the downloaded file.

        Returns:
            (list) Lines from the downloaded s3 object
        """
        lines = []
        filename, extension = os.path.splitext(downloaded_s3_object)

        if extension == '.gz':
            with gzip.open(downloaded_s3_object, 'r') as f:
                lines = f.readlines()
            # truncate file
            clear_file = gzip.open(downloaded_s3_object, 'w')
            clear_file.close()

        else:
            with open(downloaded_s3_object, 'r') as f:
                lines = f.readlines()
            # truncate file
            clear_file = open(downloaded_s3_object, 'w')
            clear_file.close()

        # remove file path
        os.remove(downloaded_s3_object)
        if not os.path.exists(downloaded_s3_object):
            logger.info('Removed temp file - %s', downloaded_s3_object)

        return lines

    @classmethod
    def parse_s3_object(cls, raw_record):
        """Given an S3 record, download and parse the data.

        Args:
            raw_record (dict): A S3 event record.

        Returns:
            (list) Lines from the downloaded s3 object
        """
        client = boto3.client('s3', region_name=raw_record['awsRegion'])
        unquote = lambda data: urllib.unquote(data).decode('utf8')
        bucket = unquote(raw_record['s3']['bucket']['name'])
        key = unquote(raw_record['s3']['object']['key'])
        size = int(raw_record['s3']['object']['size'])
        downloaded_s3_object = cls._download_s3_object(client, bucket, key, size)

        return cls._read_s3_file(downloaded_s3_object)

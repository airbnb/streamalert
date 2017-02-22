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

import logging

from collections import OrderedDict

from stream_alert.parsers import get_parser

logging.basicConfig()
logger = logging.getLogger('StreamAlert')

class InvalidSchemaError(Exception):
    """Raise this exception if a declared schema field type does not match
    the data passed."""
    pass


class StreamPayload(object):
    """Container class for the StreamAlert payload object.

    Attributes:
        raw_record: The record from the AWS Lambda Records dictionary.

        valid: A boolean representing if the record is deemed valid by
            parsing and classification.

        valid_source: A boolean of if the record source is declared in
            the sources.json configuration file.

        service: The aws service where the record originated from. Can be
            either S3 or kinesis.

        entity: The instance of the sending service. Can be either a
            specific kinesis stream or S3 bucket name.

        log_source: The name of the logging application which the data
            originated from.  This could be osquery, auditd, etc.

        type: The data type of the record - json, csv, syslog, etc.

        record: A list of parsed and typed record(s).

    Public Methods:
        refresh_record
    """

    def __init__(self, **kwargs):
        """
        Keyword Args:
            raw_record (dict): The record to be parsed - in AWS event format
        """
        self.raw_record = kwargs['raw_record']

        self.service = None
        self.entity = None
        self.type = None
        self.log_source = None
        self.records = None

        self.valid = False
        self.valid_source = None

    def __repr__(self):
        repr_str = ('<StreamPayload valid:{} '
                    'log_source:{} '
                    'entity:{} '
                    'type:{} '
                    'record:{} >'
                   ).format(self.valid,
                            self.log_source,
                            self.entity,
                            self.type,
                            self.records)

        return repr_str

    def refresh_record(self, new_record):
        """Replace the currently loaded record with a new one.

        Used mainly when S3 is used as a source, due to looping over files
        downloadd from S3 events verses all records being readily available
        from a Kinesis stream.

        Args:
            new_record (str): A new raw record to be parsed
        """
        self.raw_record = None
        self.records = None
        self.valid = None
        self.type = None
        self.raw_record = new_record


class StreamClassifier(object):
    """Classify, map source, and parse a raw record into its declared type."""
    def __init__(self, **kwargs):
        self.config = kwargs['config']

    def map_source(self, payload):
        """Map a record to its originating AWS service and entity.

        Each raw record contains a set of keys to represent its source.
        A Kinesis record will contain a `kinesis` key while a
        S3 record contains `s3`.

        Args:
            payload: A StreamAlert payload object

        Sets:
            payload.service: The AWS service which sent the record
            payload.entity: The specific instance of a service which sent the record
            payload.valid_source: Validates the record source
        """
        # check raw record for either kinesis or s3 keys
        if 'kinesis' in payload.raw_record:
            payload.service = 'kinesis'
        elif 's3' in payload.raw_record:
            payload.service = 's3'

        # map the entity name from a record
        entity_mapper = {
            'kinesis': lambda r: r['eventSourceARN'].split('/')[1],
            's3': lambda r: r['s3']['bucket']['name']
        }
        # get the entity name
        payload.entity = entity_mapper[payload.service](payload.raw_record)

        # if the payload's entity is found in the config and contains logs
        if self._payload_logs(payload):
            payload.valid_source = True

    def _payload_logs(self, payload):
        # get all logs for the configured service/enetity (s3 or kinesis)
        all_service_entities = self.config['sources'][payload.service]
        config_entity = all_service_entities.get(payload.entity)
        if config_entity:
            return config_entity['logs']
        else:
            return False

    def log_metadata(self, payload):
        """Return a mapping of all log sources to a given entity with attributes.

        Args:
            payload: A StreamAlert payload object to be mapped

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

        all_config_logs = self.config['logs']
        entity_log_sources = self._payload_logs(payload)
        for log_source, log_source_attributes in all_config_logs.iteritems():
            source_pieces = log_source.split(':')
            category = source_pieces[0]
            if category in entity_log_sources:
                metadata[log_source] = log_source_attributes

        return metadata

    def classify_record(self, payload, data):
        """Classify and type raw record passed into StreamAlert.

        Before we apply our rules to a record passed to the lambda function,
        we need to validate a record.  Validation requires verifying its source,
        checking that we have declared it in our configuration, and indeitifying
        the record's data source and parsing its data type.

        Args:
            payload: A StreamAlert payload object
            data: Pre parsed data string from a raw_event to be parsed
        """
        parse_result = self._parse(payload, data)
        if all([parse_result,
                payload.service,
                payload.entity,
                payload.type,
                payload.log_source,
                payload.records]):
            payload.valid = True

    def _parse(self, payload, data):
        """Parse a record into a declared type.

        Args:
            payload: A StreamAlert payload object
            data: Pre parsed data string from a raw_event to be parsed

        Sets:
            payload.log_source: The detected log name from the data_sources config.
            payload.type: The record's type.
            payload.records: The parsed record.

        Returns:
            A boolean representing the success of the parse.
        """
        logger.debug(data)

        log_metadata = self.log_metadata(payload)
        # TODO(jack) make this process more efficient.
        # Separate out parsing with key matching.
        # Right now, if keys match but the type/parser is correct,
        # it has to start over
        for log_name, attributes in log_metadata.iteritems():
            # short circuit parser determination
            if not payload.type:
                parser_name = attributes['parser']
            else:
                parser_name = payload.type

            options = {}
            options['hints'] = attributes.get('hints')
            options['delimiter'] = attributes.get('delimiter')
            options['separator'] = attributes.get('separator')
            options['parser'] = parser_name
            options['service'] = payload.service
            schema = attributes['schema']

            # Setup the parser
            parser_class = get_parser(parser_name)
            parser = parser_class(data, schema, options)
            options['nested_keys'] = parser.__dict__.get('nested_keys')
            # A list of parsed records
            parsed_data = parser.parse()

            # Used for short circuiting parser determination
            if parser.payload_type:
                payload.type = parser.payload_type

            logger.debug('log name: %s', log_name)
            logger.debug('parsed_data: %s', parsed_data)

            if parsed_data:
                typed_data = []
                for data in parsed_data:
                    # convert data types per the schema
                    typed_data.append(self._convert_type(data, schema, options))

                if typed_data:
                    payload.log_source = log_name
                    payload.type = parser_name
                    payload.records = typed_data
                    return True
        return False

    def _convert_type(self, parsed_data, schema, options):
        """Convert a parsed payload's values into their declared types.

        If the schema is incorrectly defined for a particular field,
        this function will return False which will make the payload
        invalid.

        Args:
            parsed_data: Parsed payload dict
            schema: data schema for a specific log source
            options: parser options dict

        Returns:
            parsed dict payload with typed values
        """
        # check for list types here
        payload = parsed_data
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
                    schema = schema[key]
                    # handle nested csv
                    if isinstance(payload[key], str):
                        options['hints'] = options['hints'][key]
                        parse_csv = get_parser('csv')
                        parsed_nested_key = parse_csv(payload[key],
                                                      schema,
                                                      options).parse()
                        # Call the first element since a list is returned
                        payload[key] = parsed_nested_key[0]
                    self._convert_type(payload[key], schema, options)
            else:
                logger.error('Invalid declared type - %s', value)

        return payload

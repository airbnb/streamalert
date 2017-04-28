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

from stream_alert.rule_processor.parsers import get_parser

logging.basicConfig()
LOGGER = logging.getLogger('StreamAlert')

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

    def __repr__(self):
        repr_str = ('<StreamPayload valid:{} log_source:{} entity:{} '
                    'type:{} record:{}>').format(self.valid, self.log_source,
                                                 self.entity, self.type, self.records)

        return repr_str

    def refresh_record(self, new_record):
        """Replace the currently loaded record with a new one.

        Used mainly when S3 is used as a source, due to looping over files
        downloadd from S3 events verses all records being readily available
        from a Kinesis stream.

        Args:
            new_record (str): A new raw record to be parsed
        """
        self.raw_record = new_record
        self.type = None
        self.log_source = None
        self.records = None
        self.valid = False


class StreamClassifier(object):
    """Classify, map source, and parse a raw record into its declared type."""
    def __init__(self, **kwargs):
        self.config = kwargs['config']
        self._entity_log_sources = []

    def map_source(self, payload):
        """Map a record to its originating AWS service and entity.

        Each raw record contains a set of keys to represent its source.
        A Kinesis record will contain a `kinesis` key while a
        S3 record contains `s3`.

        Sets:
            payload.service: The AWS service which sent the record
            payload.entity: The specific instance of a service which sent the record

        Args:
            payload: A StreamAlert payload object

        Returns:
            [boolean] True if the entity's log sources loaded properly
        """
        # Sns is capitalized below because this is how AWS stores it within the Record
        # Other services, like s3, are not stored like this. Do not alter it!
        entity_mapper = {
            'kinesis': lambda r: r['eventSourceARN'].split('/')[1],
            's3': lambda r: r['s3']['bucket']['name'],
            'Sns': lambda r: r['EventSubscriptionArn'].split(':')[5]
        }

        # check raw record for either kinesis, s3, or sns keys
        for key, map_function in entity_mapper.iteritems():
            if key in payload.raw_record:
                payload.service = key.lower()
                # map the entity name from a record
                payload.entity = map_function(payload.raw_record)
                break

        # if the payload's entity is found in the config and contains logs
        self._entity_log_sources = self._payload_logs(payload)

        return bool(self._entity_log_sources)

    def _payload_logs(self, payload):
        # get all logs for the configured service/entity (s3 or kinesis)
        all_service_entities = self.config['sources'][payload.service]
        config_entity = all_service_entities.get(payload.entity)
        if config_entity:
            return config_entity['logs']

        return False

    def _log_metadata(self):
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
                    'log_patterns': ['*pattern1*']
                }
            }
        """
        config_logs = self.config['logs']

        for log_source in config_logs:
            category = log_source.split(':')[0]
            # Remove this log type if it's not one of the sources for this entity
            if not category in self._entity_log_sources:
                config_logs.pop(log_source)

        return config_logs

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

        LOGGER.debug('payload: %s', payload)

    def _check_valid_parse(self, valid_parses):
        """Check to see if there are multiple schemas that have validly parsed this
        log. If so, fall back on using log_patterns to look for the proper log. If no
        log_patterns exist, or they do not resolve the problem, fall back on using the
        first matched schema.

        Args:
            [valid_parses] A list of tuples containing the info for schemas that have
                validly parsed this record. Each tuple is: (log_name, parser, parsed_data)

        Returns:
            [tuple] The proper tuple to use for parsing from the list of tuples
        """
        if len(valid_parses) == 1:
            return valid_parses[0]

        matched_parses = []
        for i, valid_parse in enumerate(valid_parses):
            parser = valid_parse[1]
            for data in valid_parse[2]:
                if parser.matched_log_pattern(data, parser.options.get('log_patterns', {})):
                    matched_parses.append(valid_parses[i])
                    break
                else:
                    LOGGER.debug('log pattern matching failed for schema: %s', parser.schema)

        if matched_parses:
            if len(matched_parses) > 1:
                LOGGER.error('log patterns matched for multiple schemas: %s',
                             ', '.join(name for name, _, _ in matched_parses))
                LOGGER.error('proceeding with schema for: %s', matched_parses[0][0])

            return matched_parses[0]



        LOGGER.error('log classification matched for multiple schemas: %s',
                     ', '.join(name for name, _, _ in valid_parses))
        LOGGER.error('proceeding with schema for: %s', valid_parses[0][0])

        return valid_parses[0]

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
        log_metadata = self._log_metadata()
        valid_parses = []

        # Loop over all logs declared in logs.json
        for log_name, attributes in log_metadata.iteritems():
            # get the parser type to use for this log
            parser_name = payload.type or attributes['parser']

            schema = attributes['schema']
            options = attributes.get('configuration', {})

            # Setup the parser class
            parser_class = get_parser(parser_name)
            parser = parser_class(schema, options)

            # Get a list of parsed records
            parsed_data = parser.parse(data)

            LOGGER.debug('schema: %s', schema)
            if parsed_data:
                valid_parses.append((log_name, parser, parsed_data))
                break

        if not valid_parses:
            return False

        valid_parse = self._check_valid_parse(valid_parses)

        log_name, parser, parsed_data = valid_parse[0], valid_parse[1], valid_parse[2]
        LOGGER.debug('log_name: %s', log_name)
        LOGGER.debug('parsed_data: %s', parsed_data)

        typed_data = []
        for data in parsed_data:
            # Convert data types per the schema
            # Use the parser.schema due to updates caused by
            #   configuration settings such as envelope and optional_keys
            converted_data = self._convert_type(data, parser.type(), parser.schema, parser.options)
            if not converted_data:
                payload.valid = False
                break

            typed_data.append(converted_data)

        if not typed_data:
            return False

        payload.log_source = log_name
        payload.type = parser.type()
        payload.records = parsed_data

        return True

    def _convert_type(self, payload, parser_type, schema, options):
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
        for key, value in schema.iteritems():
            key = str(key)
            # if the schema value is declared as string
            if value == 'string':
                payload[key] = str(payload[key])

            # if the schema value is declared as integer
            elif value == 'integer':
                try:
                    payload[key] = int(payload[key])
                except ValueError:
                    LOGGER.error('Invalid schema - %s is not an int', key)
                    return False

            elif value == 'float':
                try:
                    payload[key] = float(payload[key])
                except ValueError:
                    LOGGER.error('Invalid schema - %s is not a float', key)
                    return False

            elif value == 'boolean':
                payload[key] = str(payload[key]).lower() == 'true'

            elif isinstance(value, OrderedDict):
                # allow for any value to exist in the map
                if value:
                    # handle nested csv
                    # skip the 'stream_log_envelope' key that we've added during parsing
                    if key == 'stream_log_envelope' and isinstance(payload[key], dict):
                        continue

                    if 'log_patterns' in options:
                        options['log_patterns'] = options['log_patterns'][key]

                    sub_schema = schema[key]
                    parser = get_parser(parser_type)(sub_schema, options)
                    parsed_nested_key = parser.parse(payload[key])

                    # Call the first element since a list is returned
                    if parsed_nested_key:
                        payload[key] = parsed_nested_key[0]

                    self._convert_type(payload[key], parser_type, sub_schema, options)

            elif isinstance(value, list):
                pass

            else:
                LOGGER.error('Unsupported schema type: %s', value)

        return payload

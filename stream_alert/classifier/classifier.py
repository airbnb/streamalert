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
from collections import OrderedDict
import logging
from os import environ as env

from stream_alert.classifier.normalize import Normalizer
from stream_alert.classifier.parsers import get_parser
from stream_alert.classifier.payload.payload_base import StreamPayload
from stream_alert.shared import config, CLASSIFIER_FUNCTION_NAME as FUNCTION_NAME
from stream_alert.shared.logger import get_logger
from stream_alert.shared.metrics import MetricLogger
from stream_alert.shared.stats import print_rule_stats


LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)


class Classifier(object):
    """Classify, map source, and parse a raw record into its declared type."""

    _config = None

    def __init__(self, verbose=False):
        # Create some objects to be cached if they have not already been created
        Classifier._config = Classifier._config or config.load_config(validate=True)

        # Setup the normalization logic
        Normalizer.load_from_config(self.config)

        self._verbose = verbose
        self._aws_region = env.get('AWS_REGION') or env.get('AWS_DEFAULT_REGION') or 'us-east-1'
        self._payloads = []
        self._failed_record_count = 0
        self._processed_size = 0

    @property
    def config(self):
        return Classifier._config

    def _load_logs_for_resource(self, service, resource):
        """Load the log types for this service type and resource value

        Args:
            service (str): Source service
            resource (str): Resource within the service

        Returns:
            bool: True if the resource's log sources loaded properly
        """
        # Get all logs for the configured service/entity (s3, kinesis, or sns)
        resources = self._config['sources'].get(service)
        if not resources:
            LOGGER.error('Service [%s] not declared in sources configuration', service)
            return False

        source_config = resources.get(resource)
        if not source_config:
            LOGGER.error(
                'Resource [%s] not declared in sources configuration for service [%s]',
                resource,
                service)
            return False

        # Get the log schemas for source(s)
        return OrderedDict(
            (source, self.config['logs'][source])
            for source in self.config['logs'].keys()
            if source.split(':')[0] in source_config['logs']
        )

    @classmethod
    def _process_log_schemas(cls, payload_record, logs_config):
        """Get any log schemas that matched this log format

        Args:
            payload_record: A PayloadRecord object

        Returns:
            list: Contains any schemas that matched this log format
                Each list entry contains the namedtuple of 'SchemaMatch' with
                values of log_name, root_schema, parser, and parsed_data
        """
        # Loop over all logs schemas declared for this source
        for log_type, options in logs_config.iteritems():
            LOGGER.debug('Trying schema \'%s\' with options: %s', log_type, options)

            # Get the parser type to use for this log and set up the parser
            parser = get_parser(options['parser'])(options, log_type=log_type)

            parsed = parser.parse(payload_record.data)
            if not parsed:
                LOGGER.debug('Failed to classify data with schema: %s', log_type)
                continue

            # Set the parser on successful parse
            payload_record.parser = parser

            return True

        return False  #  unable to parse this record

    def run(self, records):
        """Run classificaiton of the records in the Lambda input

        Args:
            records (list): An list of records received by Lambda
        """
        LOGGER.debug('Number of incoming records: %d', len(records))
        if not records:
            return False

        for input_record in records:
            # Get the service and entity from the payload
            payload = StreamPayload.load_from_raw_record(input_record)
            if not payload:
                continue

            self._classify_payload(payload)

        self._log_metrics()

        # Only log rule info here if this is not running tests
        # During testing, this gets logged at the end and printing here could be confusing
        # since stress testing calls this method multiple times
        if self._verbose:
            print_rule_stats(True)

    def _log_bad_records(self, payload_record, records):
        for record in records:
            LOGGER.error(
                'Record does not match any defined schemas: %s\n%s', payload_record, record
            )
            self._failed_record_count += 1

    def _classify_payload(self, payload):
        """Run the record through the rules, saving any alerts and forwarding them to Dynamo.

        Args:
            payload (StreamPayload): StreamAlert payload object being processed
        """
        # Get logs defined for the service/entity in the config
        logs_config = self._load_logs_for_resource(payload.service(), payload.resource)
        if not logs_config:
            LOGGER.error(
                'No log types defined for resource [%s] in sources configuration for service [%s]',
                payload.resource,
                payload.service()
            )
            return

        for record in payload.pre_parse():
            # Increment the processed size using the length of this record
            self._processed_size += len(record)

            # Get the parser for this data
            self._process_log_schemas(record, logs_config)

            LOGGER.debug('Parsed and classified payload: %s', bool(record))

            payload.fully_classified = payload.fully_classified and record
            if not record:
                self._log_bad_records(record, [record.data])
                continue

            LOGGER.debug(
                'Classified %d record(s) with schema: %s',
                len(record.parsed_records),
                record.log_type
            )

            # Even if the parser was successful, there's a chance it
            # could not parse all records, so log them here as invalid
            self._log_bad_records(record, record.invalid_parses)

            for parsed_rec in record.parsed_records:
                Normalizer.normalize(parsed_rec, record.log_type)

            self._payloads.append(record)

    def _log_metrics(self):
        """Perform some metric logging before exiting"""
        MetricLogger.log_metric(
            FUNCTION_NAME,
            MetricLogger.TOTAL_RECORDS,
            sum(len(payload.parsed_records for payload in self._payloads))
        )

        MetricLogger.log_metric(
            FUNCTION_NAME, MetricLogger.TOTAL_PROCESSED_SIZE, self._processed_size
        )

        LOGGER.debug('Invalid record count: %d', self._failed_record_count)
        MetricLogger.log_metric(
            FUNCTION_NAME, MetricLogger.FAILED_PARSES, self._failed_record_count
        )

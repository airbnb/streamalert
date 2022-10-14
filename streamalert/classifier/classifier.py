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
import logging
import os
from collections import OrderedDict

from streamalert.classifier.clients import SQSClient
from streamalert.classifier.parsers import get_parser
from streamalert.classifier.payload.payload_base import StreamPayload
from streamalert.shared import CLASSIFIER_FUNCTION_NAME as FUNCTION_NAME
from streamalert.shared import config
from streamalert.shared.artifact_extractor import ArtifactExtractor
from streamalert.shared.exceptions import ConfigError
from streamalert.shared.firehose import FirehoseClient
from streamalert.shared.logger import get_logger
from streamalert.shared.metrics import MetricLogger
from streamalert.shared.normalize import Normalizer

LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)


class Classifier:
    """Classify, map source, and parse a raw record into its declared type."""

    _config = None
    _firehose_client = None
    _sqs_client = None

    def __init__(self):
        # Create some objects to be cached if they have not already been created
        Classifier._config = Classifier._config or config.load_config(validate=True)
        Classifier._firehose_client = (Classifier._firehose_client
                                       or FirehoseClient.load_from_config(
                                           prefix=self.config['global']['account']['prefix'],
                                           firehose_config=self.config['global'].get(
                                               'infrastructure', {}).get('firehose', {}),
                                           log_sources=self.config['logs']))
        Classifier._sqs_client = Classifier._sqs_client or SQSClient()

        # Setup the normalization logic
        Normalizer.load_from_config(self.config)
        self._cluster = os.environ['CLUSTER']
        self._payloads = []
        self._failed_record_count = 0
        self._processed_size = 0

    @property
    def config(self):
        return Classifier._config

    @property
    def classified_payloads(self):
        return self._payloads

    @property
    def firehose(self):
        return Classifier._firehose_client

    @property
    def data_retention_enabled(self):
        return Classifier._firehose_client is not None

    @property
    def sqs(self):
        return Classifier._sqs_client

    def _load_logs_for_resource(self, service, resource):
        """Load the log types for this service type and resource value

        Args:
            service (str): Source service
            resource (str): Resource within the service

        Returns:
            bool: True if the resource's log sources loaded properly
        """
        # Get all logs for the configured service/entity (s3, kinesis, or sns)
        resources = self._config['clusters'][self._cluster]['data_sources'].get(service)
        if not resources:
            error = f'Service [{service}] not declared in sources configuration for resource [{resource}]'

            raise ConfigError(error)

        source_config = resources.get(resource)
        if not source_config:
            error = f'Resource [{resource}] not declared in sources configuration for service [{service}]'

            raise ConfigError(error)

        # Get the log schemas for source(s)
        return OrderedDict((source, self.config['logs'][source])
                           for source in self.config['logs'].keys()
                           if source.split(':')[0] in source_config)

    @classmethod
    def _process_log_schemas(cls, payload_record, logs_config):
        """Get any log schemas that matched this log format

        If successful, this method sets the PayloadRecord.parser attribute to the parser
        that was used to parse the data.

        Args:
            payload_record: A PayloadRecord object
            logs_config: Subset of entire logs.json schemas to use for processing

        Returns:
            bool: True if the payload's data was successfully parsed, False otherwise
        """
        # Loop over all logs schemas declared for this source
        for log_type, options in logs_config.items():
            LOGGER.debug('Trying schema \'%s\' with options: %s', log_type, options)

            # Get the parser type to use for this log and set up the parser
            parser = get_parser(options['parser'])(options, log_type=log_type)

            parsed = parser.parse(payload_record.data)
            if not parsed:
                LOGGER.debug('Failed to classify data with schema: %s', log_type)
                continue

            LOGGER.debug('Log classified with schema: %s', log_type)

            # Set the parser on successful parse
            payload_record.parser = parser

            return True

        return False  # unable to parse this record

    def _classify_payload(self, payload):
        """Run the payload through the classification logic to determine the data type

        Args:
            payload (StreamPayload): StreamAlert payload object being processed
        """
        # Get logs defined for the service/entity in the config
        logs_config = self._load_logs_for_resource(payload.service(), payload.resource)
        if not logs_config:
            LOGGER.error(
                'No log types defined for resource [%s] in sources configuration for service [%s]',
                payload.resource, payload.service())
            return

        for record in payload.pre_parse():
            # Increment the processed size using the length of this record
            self._processed_size += len(record)

            # Get the parser for this data
            self._process_log_schemas(record, logs_config)

            LOGGER.debug('Parsed and classified payload: %s', bool(record))

            payload.fully_classified = payload.fully_classified and record
            if not record:
                self._log_bad_records(record, 1)
                continue

            LOGGER.debug('Classified %d record(s) with schema: %s', len(record.parsed_records),
                         record.log_schema_type)

            # Even if the parser was successful, there's a chance it
            # could not parse all records, so log them here as invalid
            self._log_bad_records(record, len(record.invalid_records))

            for parsed_rec in record.parsed_records:
                #
                # In Normalization v1, the normalized types are defined based on log source
                # (e.g. osquery, cloudwatch etc) and this will be deprecated.
                # In Normalization v2, the normalized types are defined based on log type
                # (e.g. osquery:differential, cloudwatch:cloudtrail, cloudwatch:events etc)
                #
                Normalizer.normalize(parsed_rec, record.log_schema_type)

            self._payloads.append(record)

    def _log_bad_records(self, payload_record, invalid_record_count):
        """Log the contents of bad records to output so they can be handled

        Args:
            payload_record (PayloadRecord): PayloadRecord instance that, when logged to output,
                prints some information that will be helpful for debugging bad data
            invalid_record_count (int): Number of invalid records to increment the count by
        """
        if not invalid_record_count:
            return  # don't log anything if the count of invalid records is not > 0

        LOGGER.error('Record does not match any defined schemas: %s', payload_record)

        self._failed_record_count += invalid_record_count

    def _log_metrics(self):
        """Perform some metric logging before exiting"""
        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.TOTAL_RECORDS,
                                sum(len(payload.parsed_records) for payload in self._payloads))
        MetricLogger.log_metric(
            FUNCTION_NAME, MetricLogger.NORMALIZED_RECORDS,
            sum(1 for payload in self._payloads for log in payload.parsed_records
                if log.get(Normalizer.NORMALIZATION_KEY)))
        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.TOTAL_PROCESSED_SIZE,
                                self._processed_size)

        LOGGER.debug('Invalid record count: %d', self._failed_record_count)
        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.FAILED_PARSES,
                                self._failed_record_count)

    def run(self, records):
        """Run classificaiton of the records in the Lambda input

        Args:
            records (list): An list of records received by Lambda
        """
        LOGGER.debug('Number of incoming records: %d', len(records))
        if not records:
            return

        for input_record in records:
            # Get the service and entity from the payload
            payload = StreamPayload.load_from_raw_record(input_record)
            if not payload:
                self._log_bad_records(input_record, 1)
                continue

            self._classify_payload(payload)

        self._log_metrics()

        # Send records to SQS before sending to Firehose
        self.sqs.send(self._payloads)

        # Send the data to firehose for historical retention
        if self.data_retention_enabled:
            categorized_records = self.firehose.send(self._payloads)

            # Extract artifacts if it is enabled
            if config.artifact_extractor_enabled(self._config):
                ArtifactExtractor(self.firehose.artifacts_firehose_stream_name(
                    self._config)).run(categorized_records)

        return self._payloads

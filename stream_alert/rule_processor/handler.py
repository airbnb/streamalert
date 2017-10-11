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
from collections import defaultdict
from logging import DEBUG as LOG_LEVEL_DEBUG
import json
import re

import backoff
import boto3
from botocore.exceptions import ClientError

from stream_alert.rule_processor import FUNCTION_NAME, LOGGER
from stream_alert.rule_processor.classifier import StreamClassifier
from stream_alert.rule_processor.config import load_config, load_env
from stream_alert.rule_processor.payload import load_stream_payload
from stream_alert.rule_processor.rules_engine import StreamRules
from stream_alert.rule_processor.threat_intel import StreamThreatIntel
from stream_alert.rule_processor.sink import StreamSink
from stream_alert.shared.backoff_handlers import (
    backoff_handler,
    success_handler,
    giveup_handler
)
from stream_alert.shared.metrics import MetricLogger

# For Firehose PutRecordBatch backoff
MAX_BACKOFF_ATTEMPTS = 10
# Adds a max of 20 seconds more to the Lambda function
MAX_BACKOFF_FIBO_VALUE = 8
# Firehose Limits: http://bit.ly/2fw5UY2
MAX_BATCH_COUNT = 500
MAX_BATCH_SIZE = 4000 * 1000
# The subtraction of 2 accounts for the newline at the end
MAX_RECORD_SIZE = 1000 * 1000 - 2


class StreamAlert(object):
    """Wrapper class for handling StreamAlert classificaiton and processing"""
    config = {}
    # Used to detect special characters in payload keys.
    # This is necessary for sanitization of data prior to searching in Athena.
    special_char_regex = re.compile(r'\W')
    special_char_sub = '_'

    def __init__(self, context, enable_alert_processor=True):
        """Initializer

        Args:
            context (dict): An AWS context object which provides metadata on the currently
                executing lambda function.
            enable_alert_processor (bool): If the user wants to send the alerts using their
                own methods, 'enable_alert_processor' can be set to False to suppress
                sending with the StreamAlert alert processor.
        """
        # Load the config. Validation occurs during load, which will
        # raise exceptions on any ConfigErrors
        StreamAlert.config = StreamAlert.config or load_config()

        # Load the environment from the context arn
        self.env = load_env(context)

        # Instantiate the sink here to handle sending the triggered alerts to the
        # alert processor
        self.sinker = StreamSink(self.env)

        # Instantiate a classifier that is used for this run
        self.classifier = StreamClassifier(config=self.config)

        self.enable_alert_processor = enable_alert_processor
        self._failed_record_count = 0
        self._processed_size = 0
        self._alerts = []

        # Create a dictionary to hold parsed payloads by log type.
        # Firehose needs this information to send to its corresponding
        # delivery stream.
        self.categorized_payloads = defaultdict(list)

        # Firehose client initialization
        self.firehose_client = None
        StreamThreatIntel.load_intelligence(self.config)

    def run(self, event):
        """StreamAlert Lambda function handler.

        Loads the configuration for the StreamAlert function which contains
        available data sources, log schemas, normalized types, and outputs.
        Classifies logs sent into a parsed type.
        Matches records against rules.

        Args:
            event (dict): An AWS event mapped to a specific source/entity
                containing data read by Lambda.

        Returns:
            bool: True if all logs being parsed match a schema
        """
        records = event.get('Records', [])
        LOGGER.debug('Number of Records: %d', len(records))
        if not records:
            return False

        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.TOTAL_RECORDS, len(records))

        firehose_config = self.config['global'].get(
            'infrastructure', {}).get('firehose', {})
        if firehose_config.get('enabled'):
            self.firehose_client = boto3.client('firehose',
                                                region_name=self.env['lambda_region'])

        for raw_record in records:
            # Get the service and entity from the payload. If the service/entity
            # is not in our config, log and error and go onto the next record
            service, entity = self.classifier.extract_service_and_entity(raw_record)
            if not service:
                LOGGER.error('No valid service found in payload\'s raw record. Skipping '
                             'record: %s', raw_record)
                continue

            if not entity:
                LOGGER.error(
                    'Unable to extract entity from payload\'s raw record for service %s. '
                    'Skipping record: %s', service, raw_record)
                continue

            # Cache the log sources for this service and entity on the classifier
            if not self.classifier.load_sources(service, entity):
                continue

            # Create the StreamPayload to use for encapsulating parsed info
            payload = load_stream_payload(service, entity, raw_record)
            if not payload:
                continue

            self._process_alerts(payload)

        MetricLogger.log_metric(FUNCTION_NAME,
                                MetricLogger.TOTAL_PROCESSED_SIZE,
                                self._processed_size)

        LOGGER.debug('Invalid record count: %d', self._failed_record_count)

        MetricLogger.log_metric(FUNCTION_NAME,
                                MetricLogger.FAILED_PARSES,
                                self._failed_record_count)

        LOGGER.debug('%s alerts triggered', len(self._alerts))

        MetricLogger.log_metric(
            FUNCTION_NAME, MetricLogger.TRIGGERED_ALERTS, len(
                self._alerts))

        # Check if debugging logging is on before json dumping alerts since
        # this can be time consuming if there are a lot of alerts
        if self._alerts and LOGGER.isEnabledFor(LOG_LEVEL_DEBUG):
            LOGGER.debug('Alerts:\n%s', json.dumps(self._alerts, indent=2))

        if self.firehose_client:
            self._send_to_firehose()

        return self._failed_record_count == 0

    def get_alerts(self):
        """Public method to return alerts from class. Useful for testing.

        Returns:
            list: list of alerts as dictionaries
        """
        return self._alerts

    @staticmethod
    def _segment_records_by_count(record_list, max_count):
        """Segment records by length

        Args:
            record_list (list): The original records list to be segmented
            max_count (int): The max amount of records to yield per group
        """
        for index in range(0, len(record_list), max_count):
            yield record_list[index:index + max_count]

    def _segment_records_by_size(self, record_batch):
        """Segment record groups by size

        Args:
            record_batch (list): The original record batch to measure and segment

        Returns:
            generator: Used to iterate on each newly segmented group
        """
        split_factor = 1
        len_batch = len(record_batch)

        # Sample the first batch of records to determine the split factor.
        # Generally, it's very rare for a group of records to have
        # drastically different sizes in a single Lambda invocation.
        while len(json.dumps(record_batch[:len_batch / split_factor],
                             separators=(",", ":"))) > MAX_BATCH_SIZE:
            split_factor += 1

        return self._segment_records_by_count(record_batch, len_batch / split_factor)

    @staticmethod
    def _limit_record_size(batch):
        """Limit the record size to be sent to Firehose

        Args:
            batch (list): Record batch to iterate on
        """
        for index, record in enumerate(batch):
            if len(json.dumps(record, separators=(",", ":"))) > MAX_RECORD_SIZE:
                # Show the first 1k bytes in order to not overload
                # CloudWatch logs
                LOGGER.error('The following record is too large'
                             'be sent to Firehose: %s', str(record)[:1000])
                MetricLogger.log_metric(FUNCTION_NAME,
                                        MetricLogger.FIREHOSE_FAILED_RECORDS,
                                        1)
                batch.pop(index)

    @classmethod
    def sanitize_keys(cls, record):
        """Remove special characters from parsed record keys

        This is required when searching in Athena.  Keys can only have
        a period or underscore

        Args:
            record (dict): Original parsed record

        Returns:
            dict: A sanitized record
        """
        new_record = {}
        for key, value in record.iteritems():
            sanitized_key = re.sub(cls.special_char_regex,
                                   cls.special_char_sub,
                                   key)

            # Handle nested objects
            if isinstance(value, dict):
                new_record[sanitized_key] = cls.sanitize_keys(record[key])
            else:
                new_record[sanitized_key] = record[key]

        return new_record

    def _firehose_request_helper(self, stream_name, record_batch):
        """Send record batches to Firehose

        Args:
            stream_name (str): The name of the Delivery Stream to send to
            record_batch (list): The records to send
        """
        resp = {}
        record_batch_size = len(record_batch)

        @backoff.on_predicate(backoff.fibo,
                              lambda resp: resp['FailedPutCount'] > 0,
                              max_tries=MAX_BACKOFF_ATTEMPTS,
                              max_value=MAX_BACKOFF_FIBO_VALUE,
                              jitter=backoff.full_jitter,
                              on_backoff=backoff_handler,
                              on_success=success_handler,
                              on_giveup=giveup_handler)
        @backoff.on_exception(backoff.fibo,
                              ClientError,
                              max_tries=MAX_BACKOFF_ATTEMPTS,
                              jitter=backoff.full_jitter,
                              on_backoff=backoff_handler,
                              on_success=success_handler,
                              on_giveup=giveup_handler)
        def firehose_request_wrapper():
            """Firehose request wrapper to use with backoff"""
            LOGGER.info('[Firehose] Sending %d records to %s',
                        record_batch_size,
                        stream_name)
            return self.firehose_client.put_record_batch(
                DeliveryStreamName=stream_name,
                # The newline at the end is required by Firehose,
                # otherwise all records will be on a single line and
                # unsearchable in Athena.
                Records=[{'Data': json.dumps(self.sanitize_keys(record),
                                             separators=(",", ":")) + '\n'}
                         for record
                         in record_batch])

        # The try/except here is to catch the raised error at the
        # end of the backoff.
        try:
            resp = firehose_request_wrapper()
        except ClientError as firehose_err:
            LOGGER.error(firehose_err)
            MetricLogger.log_metric(FUNCTION_NAME,
                                    MetricLogger.FIREHOSE_FAILED_RECORDS,
                                    record_batch_size)
            return

        # Error handle if failures occured in PutRecordBatch after
        # several backoff attempts
        if resp.get('FailedPutCount') > 0:
            failed_records = [failed
                              for failed
                              in resp['RequestResponses']
                              if failed.get('ErrorCode')]
            MetricLogger.log_metric(FUNCTION_NAME,
                                    MetricLogger.FIREHOSE_FAILED_RECORDS,
                                    resp['FailedPutCount'])
            # Only print the first 100 failed records to Cloudwatch logs
            LOGGER.error('[Firehose] The following records failed to put to '
                         'the Delivery Stream %s: %s',
                         stream_name,
                         json.dumps(failed_records[:100], indent=2))
        else:
            MetricLogger.log_metric(FUNCTION_NAME,
                                    MetricLogger.FIREHOSE_RECORDS_SENT,
                                    record_batch_size)
            LOGGER.info('[Firehose] Successfully sent %d messages to %s',
                        record_batch_size,
                        stream_name)

    def _send_to_firehose(self):
        """Send all classified records to a respective Firehose Delivery Stream"""
        delivery_stream_name_pattern = 'streamalert_data_{}'

        # Iterate through each payload type
        for log_type, records in self.categorized_payloads.items():
            # This same method is used when naming the Delivery Streams
            formatted_log_type = log_type.replace(':', '_')

            for record_batch in self._segment_records_by_count(records, MAX_BATCH_COUNT):
                stream_name = delivery_stream_name_pattern.format(formatted_log_type)
                self._limit_record_size(record_batch)
                for sized_batch in self._segment_records_by_size(record_batch):
                    self._firehose_request_helper(stream_name, sized_batch)

    def _process_alerts(self, payload):
        """Process records for alerts and send them to the correct places

        Args:
            payload (StreamPayload): StreamAlert payload object being processed
        """
        for record in payload.pre_parse():
            # Increment the processed size using the length of this record
            self._processed_size += len(record.pre_parsed_record)
            self.classifier.classify_record(record)
            if not record.valid:
                if self.env['lambda_alias'] != 'development':
                    LOGGER.error('Record does not match any defined schemas: %s\n%s',
                                 record, record.pre_parsed_record)

                self._failed_record_count += 1
                continue

            LOGGER.debug(
                'Classified and Parsed Payload: <Valid: %s, Log Source: %s, Entity: %s>',
                record.valid,
                record.log_source,
                record.entity)

            record_alerts = StreamRules.process(record)

            LOGGER.debug('Processed %d valid record(s) that resulted in %d alert(s).',
                         len(payload.records),
                         len(record_alerts))

            # Add all parsed records to the categorized payload dict
            # only if Firehose is enabled
            if self.firehose_client:
                # Only send payloads with enabled types
                if payload.log_source.split(':')[0] not in self.config['global'] \
                    ['infrastructure'].get('firehose', {}).get('disabled_logs', []):
                    self.categorized_payloads[payload.log_source].extend(payload.records)

            if not record_alerts:
                continue

            # Extend the list of alerts with any new ones so they can be returned
            self._alerts.extend(record_alerts)

            if self.enable_alert_processor:
                self.sinker.sink(record_alerts)

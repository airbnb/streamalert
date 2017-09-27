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

import boto3

from stream_alert.rule_processor import FUNCTION_NAME, LOGGER
from stream_alert.rule_processor.classifier import StreamClassifier
from stream_alert.rule_processor.config import load_config, load_env
from stream_alert.rule_processor.payload import load_stream_payload
from stream_alert.rule_processor.rules_engine import StreamRules
from stream_alert.rule_processor.sink import StreamSink
from stream_alert.shared.metrics import MetricLogger


MAX_RECORD_SIZE = 1000 * 1000
MAX_BATCH_SIZE = 500


class StreamAlert(object):
    """Wrapper class for handling StreamAlert classificaiton and processing"""
    __config = {}

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
        StreamAlert.__config = StreamAlert.__config or load_config()

        # Load the environment from the context arn
        self.env = load_env(context)

        # Instantiate the sink here to handle sending the triggered alerts to the
        # alert processor
        self.sinker = StreamSink(self.env)

        # Instantiate a classifier that is used for this run
        self.classifier = StreamClassifier(config=self.__config)

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

        firehose_config = self.__config['global'].get(
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

    def _send_to_firehose(self):
        """Send all classified records to a respective Firehose Delivery Stream"""
        def _chunk(record_list, chunk_size):
            """Helper function to chunk payloads"""
            for item in range(0, len(record_list), chunk_size):
                yield record_list[item:item + chunk_size]

        def _check_record_batch(batch):
            """Helper function to verify record size"""
            for index, record in enumerate(batch):
                if len(str(record)) > MAX_RECORD_SIZE:
                    # Show the first 1k bytes in order to not overload
                    # CloudWatch logs
                    LOGGER.error('The following record is too large'
                                 'be sent to Firehose: %s', str(record)[:1000])
                    MetricLogger.log_metric(FUNCTION_NAME,
                                            MetricLogger.FIREHOSE_FAILED_RECORDS,
                                            1)
                    batch.pop(index)

        delivery_stream_name_pattern = 'streamalert_data_{}'

        # Iterate through each payload type
        for log_type, records in self.categorized_payloads.items():
            # This same method is used when naming the Delivery Streams
            formatted_log_type = log_type.replace(':', '_')

            for record_batch in _chunk(records, MAX_BATCH_SIZE):
                stream_name = delivery_stream_name_pattern.format(formatted_log_type)
                _check_record_batch(record_batch)

                resp = self.firehose_client.put_record_batch(
                    DeliveryStreamName=stream_name,
                    # The newline at the end is required by Firehose,
                    # otherwise all records will be on a single line and
                    # unsearchable in Athena.
                    Records=[{'Data': json.dumps(record, separators=(",", ":")) + '\n'}
                             for record
                             in record_batch])

                # Error handle if failures occured
                # TODO(jack) implement backoff here once the rule processor is split
                if resp.get('FailedPutCount') > 0:
                    failed_records = [failed
                                      for failed
                                      in resp['RequestResponses']
                                      if failed.get('ErrorCode')]
                    MetricLogger.log_metric(FUNCTION_NAME,
                                            MetricLogger.FIREHOSE_FAILED_RECORDS,
                                            resp['FailedPutCount'])
                    # Only print the first 100 failed records
                    LOGGER.error('The following records failed to Put to the'
                                 'Delivery stream %s: %s',
                                 stream_name,
                                 json.dumps(failed_records[:100], indent=2))
                else:
                    MetricLogger.log_metric(FUNCTION_NAME,
                                            MetricLogger.FIREHOSE_RECORDS_SENT,
                                            len(record_batch))
                    LOGGER.info('Successfully sent %d messages to Firehose:%s',
                                len(record_batch),
                                stream_name)

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
                self.categorized_payloads[payload.log_source].extend(payload.records)

            if not record_alerts:
                continue

            # Extend the list of alerts with any new ones so they can be returned
            self._alerts.extend(record_alerts)

            if self.enable_alert_processor:
                self.sinker.sink(record_alerts)

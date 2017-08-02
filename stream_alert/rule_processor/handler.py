import json
import logging
import os

from stream_alert.rule_processor.config import load_config, load_env
from stream_alert.rule_processor.classifier import StreamPayload, StreamClassifier
from stream_alert.rule_processor.pre_parsers import StreamPreParsers
from stream_alert.rule_processor.rules_engine import StreamRules
from stream_alert.rule_processor.sink import StreamSink

logging.basicConfig()
LEVEL = os.environ.get('LOGGER_LEVEL', 'INFO')
LOGGER = logging.getLogger('StreamAlert')
LOGGER.setLevel(LEVEL.upper())


class StreamAlert(object):
    """Wrapper class for handling all StreamAlert classificaiton and processing"""
    def __init__(self, context, enable_alert_processor=True):
        """
        Args:
            context: An AWS context object which provides metadata on the currently
                executing lambda function.
            enable_alert_processor: If the user wants to send the alerts using their
                own methods, 'enable_alert_processor' can be set to False to suppress
                sending with the StreamAlert alert processor.
        """
        self.env = load_env(context)
        self.enable_alert_processor = enable_alert_processor
        # Instantiate the sink here to handle sending the triggered alerts to the alert processor
        self.sinker = StreamSink(self.env)
        self._failed_record_count = 0
        self._alerts = []

    def run(self, event):
        """StreamAlert Lambda function handler.

        Loads the configuration for the StreamAlert function which contains:
        available data sources, log formats, parser modes, and sinks.  Classifies
        logs sent into the stream into a parsed type.  Matches records against
        rules.

        Args:
            event: An AWS event mapped to a specific source/entity (kinesis stream or
                an s3 bucket event) containing data emitted to the stream.

        Returns:
            [boolean] True if all logs being parsed match a schema
        """
        LOGGER.debug('Number of Records: %d', len(event.get('Records', [])))

        config = load_config()

        for record in event.get('Records', []):
            payload = StreamPayload(raw_record=record)
            classifier = StreamClassifier(config=config)

            # If the kinesis stream, s3 bucket, or sns topic is not in our config,
            # go onto the next record
            if not classifier.map_source(payload):
                continue

            if payload.service == 's3':
                self._s3_process(payload, classifier)
            elif payload.service == 'kinesis':
                self._kinesis_process(payload, classifier)
            elif payload.service == 'sns':
                self._sns_process(payload, classifier)
            else:
                LOGGER.error('Unsupported service: %s', payload.service)

        LOGGER.debug('%s alerts triggered', len(self._alerts))
        LOGGER.debug('\n%s\n', json.dumps(self._alerts, indent=4))

        return self._failed_record_count == 0

    def get_alerts(self):
        """Public method to return alerts from class. Useful for testing.

        Returns:
            [list] list of alerts as dictionaries
        """
        return self._alerts

    def _kinesis_process(self, payload, classifier):
        """Process Kinesis data for alerts"""
        data = StreamPreParsers.pre_parse_kinesis(payload.raw_record)
        self._process_alerts(classifier, payload, data)

    def _s3_process(self, payload, classifier):
        """Process S3 data for alerts"""
        s3_file, s3_object_size = StreamPreParsers.pre_parse_s3(payload.raw_record)
        count, processed_size = 0, 0
        for data in StreamPreParsers.read_s3_file(s3_file):
            payload.refresh_record(data)
            self._process_alerts(classifier, payload, data)
            # Add the current data to the total processed size, +1 to account for line feed
            processed_size += (len(data) + 1)
            count += 1
            # Log an info message on every 100 lines processed
            if count % 100 == 0:
                avg_record_size = ((processed_size - 1) / count)
                approx_record_count = s3_object_size / avg_record_size
                LOGGER.info('Processed %s records out of an approximate total of %s '
                            '(average record size: %s bytes, total size: %s bytes)',
                            count, approx_record_count, avg_record_size, s3_object_size)

    def _sns_process(self, payload, classifier):
        """Process SNS data for alerts"""
        data = StreamPreParsers.pre_parse_sns(payload.raw_record)
        self._process_alerts(classifier, payload, data)

    def _process_alerts(self, classifier, payload, data):
        """Process records for alerts and send them to the correct places

        Args:
            classifier [StreamClassifier]: Handler for classifying a record's data
            payload [StreamPayload]: StreamAlert payload object being processed
            data [string]: Pre parsed data string from a raw_event to be parsed
        """
        classifier.classify_record(payload, data)
        if not payload.valid:
            if self.env['lambda_alias'] != 'development':
                LOGGER.error('Record does not match any defined schemas: %s\n%s', payload, data)
            self._failed_record_count += 1
            return

        alerts = StreamRules.process(payload)

        LOGGER.debug('Processed %d valid record(s) that resulted in %d alert(s).',
                     len(payload.records),
                     len(alerts))

        if not alerts:
            return

        # Extend the list of alerts with any new ones so they can be returned
        self._alerts.extend(alerts)

        if self.enable_alert_processor:
            self.sinker.sink(alerts)

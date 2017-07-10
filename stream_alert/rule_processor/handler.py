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
    def __init__(self, context, return_alerts=False):
        """
        Args:
            context: An AWS context object which provides metadata on the currently
                executing lambda function.
            return_alerts: If the user wants to handle the sinking
                of alerts to external endpoints, return a list of
                generated alerts.
        """
        self.return_alerts = return_alerts
        self.env = load_env(context)
        # Instantiate the sink here to handle sending the triggered alerts to the alert processor
        self.sinker = StreamSink(self.env)
        self.alerts = []

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
            None
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
                LOGGER.info('Unsupported service: %s', payload.service)

        LOGGER.debug('%s alerts triggered', len(self.alerts))
        LOGGER.debug('\n%s\n', json.dumps(self.alerts, indent=4))

        if self.return_alerts:
            return self.alerts

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
            LOGGER.error('Invalid data: %s\n%s', payload, data)
            return

        alerts = StreamRules.process(payload)
        if not alerts:
            LOGGER.debug('Valid data, no alerts')
            return

        # If we want alerts returned to the caller, extend the list. Otherwise
        # attempt to send them to the alert processor
        if self.return_alerts:
            self.alerts.extend(alerts)
        else:
            self.sinker.sink(alerts)

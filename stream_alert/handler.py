import json
import logging
import os

from stream_alert.config import load_config, load_env
from stream_alert.classifier import StreamPayload, StreamClassifier
from stream_alert.pre_parsers import StreamPreParsers
from stream_alert.rules_engine import StreamRules
from stream_alert.sink import StreamSink

logging.basicConfig()
logger = logging.getLogger('StreamAlert')
logger.setLevel(logging.INFO)

class StreamAlert(object):
    """Wrapper class for handling all StreamAlert classificaiton and processing"""
    def __init__(self, **kwargs):
        """
        Args:
            return_alerts: If the user wants to handle the sinking
                of alerts to external endpoints, return a list of
                generated alerts.
        """
        self.return_alerts = kwargs.get('return_alerts')
        self.alerts = []

    def run(self, event, context):
        """StreamAlert Lambda function handler.

        Loads the configuration for the StreamAlert function which contains:
        available data sources, log formats, parser modes, and sinks.  Classifies
        logs sent into the stream into a parsed type.  Matches records against
        rules.

        Args:
            event: An AWS event mapped to a specific source/entity (kinesis stream or
                an s3 bucket event) containing data emitted to the stream.
            context: An AWS context object which provides metadata on the currently
                executing lambda function.

        Returns:
            None
        """
        logger.debug('Number of Records: %d', len(event.get('Records')))

        config = load_config()
        env = load_env(context)

        for record in event.get('Records'):
            payload = StreamPayload(raw_record=record)
            classifier = StreamClassifier(config=config)
            classifier.map_source(payload)

            # If the kinesis stream or s3 bucket is not in our config,
            # go onto the next record
            if not payload.valid_source:
                continue

            if payload.service == 's3':
                self.s3_process(payload, classifier)
            elif payload.service == 'kinesis':
                self.kinesis_process(payload, classifier)
            else:
                logger.info('Unsupported service: %s', payload.service)

        # Give the user control over handling generated alerts
        if self.return_alerts:
            return self.alerts
        else:
            self.send_alerts(env)

    def kinesis_process(self, payload, classifier):
        """Process Kinesis data for alerts"""
        data = StreamPreParsers.pre_parse_kinesis(payload.raw_record)
        classifier.classify_record(payload, data)
        self.process_alerts(payload)

    def s3_process(self, payload, classifier):
        """Process S3 data for alerts"""
        s3_file_lines = StreamPreParsers.pre_parse_s3(payload.raw_record)
        for line in s3_file_lines:
            data = line.rstrip()
            payload.refresh_record(data)
            classifier.classify_record(payload, data)
            self.process_alerts(payload)

    def send_alerts(self, env):
        """Send generated alerts to correct places"""
        if self.alerts:
            if env['lambda_alias'] == 'development':
                logger.info('%s alerts triggered', len(self.alerts))
                logger.info('\n%s\n', json.dumps(self.alerts, indent=4))
            else:
                StreamSink(self.alerts, config, env).sink()
        else:
            logger.debug('Valid data, no alerts: %s', payload)

    def process_alerts(self, payload):
        """Process records for alerts"""
        if payload.valid:
            alerts = StreamRules.process(payload)
            if alerts:
                self.alerts.extend(alerts)
        else:
            logger.debug('Invalid data: %s', payload)

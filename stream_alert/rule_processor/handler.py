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
import json
import math

from copy import copy
from logging import DEBUG as log_level_debug
import multiprocessing as multiproc

from stream_alert.rule_processor import LOGGER
from stream_alert.rule_processor.config import load_config, load_env
from stream_alert.rule_processor.classifier import StreamClassifier
from stream_alert.rule_processor.payload import load_stream_payload
from stream_alert.rule_processor.rules_engine import StreamRules
from stream_alert.rule_processor.sink import StreamSink
from stream_alert.shared.metrics import Metrics
from stream_alert.shared.stats import time_me

PROC_MANAGER = multiproc.Manager()


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
        # Load the config. Validation occurs during load, which will
        # raise exceptions on any ConfigErrors
        config = load_config()

        # Load the environment from the context arn
        self.env = load_env(context)

        # Instantiate the sink here to handle sending the triggered alerts to the
        # alert processor
        self.sinker = StreamSink(self.env)

        # Instantiate a classifier that is used for this run
        self.classifier = StreamClassifier(config=config)

        self.metrics = Metrics('RuleProcessor', self.env['lambda_region'])
        self.enable_alert_processor = enable_alert_processor
        self._unmatched_record_count = PROC_MANAGER.Value('i', 0)
        self._alerts = PROC_MANAGER.list()

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
        records = event.get('Records', [])
        LOGGER.debug('Number of Records: %d', len(records))
        if not records:
            return False

        self.metrics.add_metric(
            Metrics.Name.TOTAL_RECORDS,
            len(records),
            Metrics.Unit.COUNT)

        workers = []
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
            payload = load_stream_payload(service, entity, raw_record, self.metrics)
            if not payload:
                continue

            self._run_batches(payload, workers)

        LOGGER.debug('Number of running workers: %d', len(workers))

        # Wait for all of the workers to finish before continuing
        for worker in workers:
            worker.join()

        if self._unmatched_record_count.value:
            LOGGER.debug('Invalid record count: %d', self._unmatched_record_count.value)

        self.metrics.add_metric(
            Metrics.Name.FAILED_PARSES,
            self._unmatched_record_count.value,
            Metrics.Unit.COUNT)

        LOGGER.info('%s alerts triggered', len(self._alerts))

        self.metrics.add_metric(
            Metrics.Name.TRIGGERED_ALERTS, len(
                self._alerts), Metrics.Unit.COUNT)

        # Check if debugging logging is on before json dumping alerts since
        # this can be time consuming if there are a lot of alerts
        if self._alerts and LOGGER.isEnabledFor(log_level_debug):
            LOGGER.debug('Alerts:\n%s', json.dumps(self.get_alerts(), indent=2))

        # Send any cached metrics to CloudWatch before returning
        self.metrics.send_metrics()

        return self._unmatched_record_count.value == 0

    def get_alerts(self):
        """Public method to return alerts from class. Useful for testing.

        Returns:
            [list] list of alerts as dictionaries
        """
        # Call through to return the underlying list value from the ListProxy
        return self._alerts._getvalue()

    def _run_batches(self, payload, workers):
        """Get all of the pre-parsed records from the payload and segment them
        into chunks to be spread accross multiprocessing workers.

        Args:
            payload [StreamPayload]: StreamAlert payload object being processed
            workers [list<mutliprocessing.Process>]: The complete list of
                multiprocessing jobs to append this job to
        """
        # Get all of the pre-parsed records from the generator for this payload
        payload_records = list(payload.pre_parse())

        # Default to spawning 2 processes per available CPU
        num_workers = multiproc.cpu_count() * 2

        LOGGER.debug('Creating a maximum of %d workers for processing', num_workers)

        # Get the interval that we should segment the list of alerts on and
        # arrange them into sublists of this size. Default to minimum of 1
        interval = int(math.ceil(len(payload_records)/float(num_workers))) or 1
        record_groups = [payload_records[index:interval+index]
                         for index in range(0, len(payload_records), interval)]

        # Create a lock that can be used within spawned processes
        mutex = PROC_MANAGER.Lock()

        for worker_index, record_group in enumerate(record_groups, start=1):
            offset = (worker_index - 1) * interval
            LOGGER.debug('Running worker #%d for %d-%d of %d records',
                         worker_index, offset + 1, offset + len(record_group),
                         len(payload_records))
            # Create a copy of the classifier for each worker being created
            # to avoid conflicts with the workers sharing the cached classifier
            worker_classifier = copy(self.classifier)
            processor = multiproc.Process(
                target=self._process_alerts, args=(worker_classifier, record_group, mutex))
            workers.append(processor)
            processor.start()

    @time_me
    def _process_alerts(self, worker_classifier, records, mutex):
        """Process records for alerts and send them to the correct places

        Args:
            classifier [StreamClassifier]: A copy of the cached StreamClassifier
                that should be used to classify this list of records
            records [list]: A batch of records to be processed from the list of
                pre-parsed records.
        """
        for record in records:
            worker_classifier.classify_record(record)
            if not record.valid:
                if self.env['lambda_alias'] != 'development':
                    LOGGER.error('Record does not match any defined schemas: %s\n%s',
                                 record, record.pre_parsed_record)

                with mutex:
                    self._unmatched_record_count.value += 1
                continue

            LOGGER.debug('Classified and Parsed Payload: <Valid: %s, Log Source: %s, Entity: %s>',
                         record.valid, record.log_source, record.entity)

            record_alerts = StreamRules.process(record)

            LOGGER.debug('Processed %d valid record(s) that resulted in %d alert(s).',
                         len(record.records),
                         len(record_alerts))

            if not record_alerts:
                continue

            # Get a lock in this process so we can extend the list of alerts
            # with any new ones and try to send them to the alert processor
            with mutex:
                self._alerts.extend(record_alerts)

                if self.enable_alert_processor:
                    self.sinker.sink(record_alerts)

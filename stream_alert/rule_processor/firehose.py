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
import json
import re

import backoff
import boto3
from botocore.exceptions import ClientError
from botocore.vendored.requests.exceptions import ConnectionError

from stream_alert.rule_processor import FUNCTION_NAME, LOGGER
from stream_alert.shared.metrics import MetricLogger
from stream_alert.shared.backoff_handlers import (
    backoff_handler,
    success_handler,
    giveup_handler
)

class StreamAlertFirehose(object):
    """Handles preparing and sending data from the Rule Processor to Kinesis Firehose"""
    # Used to detect special characters in payload keys.
    # This is necessary for sanitization of data prior to searching in Athena.
    SPECIAL_CHAR_REGEX = re.compile(r'\W')
    SPECIAL_CHAR_SUB = '_'
    # For PutRecordBatch backoff
    MAX_BACKOFF_ATTEMPTS = 10
    # Adds a max of 20 seconds more to the Lambda function
    MAX_BACKOFF_FIBO_VALUE = 8
    # Set Firehose Limits: http://bit.ly/2fw5UY2
    MAX_BATCH_COUNT = 500
    MAX_BATCH_SIZE = 4000 * 1000
    # The subtraction of 2 accounts for the newline at the end
    MAX_RECORD_SIZE = 1000 * 1000 - 2

    def __init__(self, region, firehose_config, log_sources):
        self._firehose_client = boto3.client('firehose', region_name=region)
        # Expand enabled logs into specific subtypes

        self._enabled_logs = []
        if firehose_config:
            self._enabled_logs = self._load_enabled_log_sources(firehose_config, log_sources)
        # Create a dictionary to hold parsed payloads by log type.
        # Firehose needs this information to send to its corresponding
        # delivery stream.
        self.categorized_payloads = defaultdict(list)

    @property
    def enabled_logs(self):
        """Enabled Logs Property

        Returns:
            list: casts the set of enabled logs into a list for JSON serialization"""
        return list(self._enabled_logs)

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
                             separators=(",", ":"))) > self.MAX_BATCH_SIZE:
            split_factor += 1

        return self._segment_records_by_count(record_batch, len_batch / split_factor)

    @staticmethod
    def _segment_records_by_count(record_list, max_count):
        """Segment records by length

        Args:
            record_list (list): The original records list to be segmented
            max_count (int): The max amount of records to yield per group
        """
        for index in range(0, len(record_list), max_count):
            yield record_list[index:index + max_count]

    @classmethod
    def _limit_record_size(cls, batch):
        """Limits the batch size sent to Firehose by popping large records

        Args:
            batch (list): Record batch to iterate on
        """
        for index, record in enumerate(batch):
            if len(json.dumps(record, separators=(",", ":"))) > cls.MAX_RECORD_SIZE:
                # Show the first 1k bytes in order to not overload CloudWatch logs
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
            sanitized_key = re.sub(cls.SPECIAL_CHAR_REGEX, cls.SPECIAL_CHAR_SUB, key)

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
        exceptions_to_backoff = (ClientError, ConnectionError)

        @backoff.on_predicate(backoff.fibo,
                              lambda resp: resp['FailedPutCount'] > 0,
                              max_tries=self.MAX_BACKOFF_ATTEMPTS,
                              max_value=self.MAX_BACKOFF_FIBO_VALUE,
                              jitter=backoff.full_jitter,
                              on_backoff=backoff_handler,
                              on_success=success_handler,
                              on_giveup=giveup_handler)
        @backoff.on_exception(backoff.fibo,
                              exceptions_to_backoff,
                              max_tries=self.MAX_BACKOFF_ATTEMPTS,
                              jitter=backoff.full_jitter,
                              on_backoff=backoff_handler,
                              on_success=success_handler,
                              on_giveup=giveup_handler)
        def firehose_request_wrapper():
            """Firehose request wrapper to use with backoff"""
            LOGGER.info('[Firehose] Sending %d records to %s',
                        record_batch_size,
                        stream_name)
            return self._firehose_client.put_record_batch(
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
        except exceptions_to_backoff as firehose_err:
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
            LOGGER.info('[Firehose] Successfully sent %d messages to %s with RequestId [%s]',
                        record_batch_size,
                        stream_name,
                        resp.get('ResponseMetadata', {}).get('RequestId', ''))

    def firehose_log_name(self, log_name):
        """Convert conventional log names into Firehose delievery stream names

        Args:
            log_name: The name of the log from logs.json

        Returns
            str: Converted name which corresponds to a Firehose Delievery Stream
        """
        return re.sub(self.SPECIAL_CHAR_REGEX, '_', log_name)

    def enabled_log_source(self, log_source_name):
        """Check that the incoming record is an enabled log source for Firehose

        Args:
            log_source_name (str): The log source of the record

        Returns:
            bool: Whether or not the log source is enabled to send to Firehose
        """
        return self.firehose_log_name(log_source_name) in self.enabled_logs

    def _load_enabled_log_sources(self, firehose_config, log_sources):
        """Load and expand all declared and enabled Firehose log sources

        Args:
            firehose_config (dict): Loaded Firehose config from global.json
            log_sources (dict): Loaded logs.json file

        Returns:
            set: Disabled logs
        """
        enabled_logs = set()
        for enabled_log in firehose_config.get('enabled_logs', []):
            enabled_log_parts = enabled_log.split(':')

            # Expand to all subtypes
            if len(enabled_log_parts) == 1:
                expanded_logs = [self.firehose_log_name(log_name) for log_name
                                 in log_sources
                                 if log_name.split(':')[0] == enabled_log_parts[0]]
                # If the list comprehension is Falsey, it means no matching logs
                # were found while doing the expansion.
                if not expanded_logs:
                    LOGGER.error('Enabled Firehose log %s not declared in logs.json', enabled_log)

                enabled_logs.update(expanded_logs)

            elif len(enabled_log_parts) == 2:
                if enabled_log not in log_sources:
                    LOGGER.error('Enabled Firehose log %s not declared in logs.json', enabled_log)

                enabled_logs.add(self.firehose_log_name('_'.join(enabled_log_parts)))

        return enabled_logs

    def send(self):
        """Send all classified records to a respective Firehose Delivery Stream"""
        delivery_stream_name_pattern = 'streamalert_data_{}'

        # Iterate through each set of categorized payloads.
        # Each batch will be processed to their specific Firehose, which lands the data
        # in a specific prefix in S3.
        for log_type, records in self.categorized_payloads.iteritems():
            # This same substitution method is used when naming the Delivery Streams
            formatted_log_type = self.firehose_log_name(log_type)

            # Process each record batch in the categorized payload set
            for record_batch in self._segment_records_by_count(records, self.MAX_BATCH_COUNT):
                stream_name = delivery_stream_name_pattern.format(formatted_log_type)
                self._limit_record_size(record_batch)
                for sized_batch in self._segment_records_by_size(record_batch):
                    self._firehose_request_helper(stream_name, sized_batch)

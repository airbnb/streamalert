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
import hashlib
import json
import re
from collections import defaultdict

import backoff
import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import ConnectionError as BotocoreConnectionError
from botocore.exceptions import HTTPClientError

import streamalert.shared.helpers.boto as boto_helpers
from streamalert.shared import CLASSIFIER_FUNCTION_NAME
from streamalert.shared.backoff_handlers import (backoff_handler,
                                                 giveup_handler,
                                                 success_handler)
from streamalert.shared.logger import get_logger
from streamalert.shared.metrics import MetricLogger

LOGGER = get_logger(__name__)


class FirehoseClient:
    """Handles preparing and sending data from the classifier function to Kinesis Firehose"""
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

    # Default firehose name format, should be formatted with deployment prefix
    DEFAULT_FIREHOSE_FMT = '{}streamalert_{}'

    # Exception for which backoff operations should be performed
    EXCEPTIONS_TO_BACKOFF = (ClientError, BotocoreConnectionError, HTTPClientError)

    # Set of enabled log types for firehose, loaded from configs
    _ENABLED_LOGS = {}

    # The max length of the firehose stream name is 64. For streamalert data firehose,
    # we reserve 12 chars to have `streamalert_` as part of prefix. Please refer to
    # terraform/modules/tf_kinesis_firehose_delivery_stream/main.tf
    AWS_FIREHOSE_NAME_MAX_LEN = 64

    FIREHOSE_NAME_MIN_HASH_LEN = 8

    def __init__(self, prefix, firehose_config=None, log_sources=None):
        self._prefix = prefix if firehose_config and firehose_config.get('use_prefix', True) else ''
        self._client = boto3.client('firehose', config=boto_helpers.default_config())
        self.load_enabled_log_sources(firehose_config, log_sources, force_load=True)

    @classmethod
    def _records_to_json_list(cls, records):
        """Write the dictionary records to json lines and return the list of lines

        Args:
            records (list<dict>): Records to be written to line-delimited json

        Returns:
            list: JSON serialized records
        """
        # Write the json lines to the object in minimal form
        return [
            json.dumps(cls.sanitize_keys(record), separators=(',', ':')) + '\n'
            for record in records
        ]

    @classmethod
    def _record_batches(cls, records, function_name):
        """Segment the records into batches that conform to Firehose restrictions

        This will log any single record that is too large to send, and skip it.

        Args:
            records (list): The original records list to be segmented

        Yields:
            list: Batches of JSON serialized records that conform to Firehose restrictions
        """
        records_json = cls._records_to_json_list(records)

        current_batch_size = 0
        current_batch = []
        for record in records_json:
            line_len = len(record)
            # Check if the max size of the batch has been reached or if the current
            # record will exceed the max batch size and start a new batch
            if ((len(current_batch) == cls.MAX_BATCH_COUNT) or
                (current_batch_size + line_len > cls.MAX_BATCH_SIZE)) and current_batch:
                yield current_batch[:]
                current_batch_size = 0
                del current_batch[:]

            if line_len > cls.MAX_RECORD_SIZE:
                LOGGER.error('Record too large (%d) to send to Firehose:\n%s', line_len, record)
                cls._log_failed(1, function_name)
                continue

            # Add the record to the batch
            current_batch_size += line_len
            current_batch.append(record)

        # yield the result of the last batch (no need to copy via slicing)
        if current_batch:
            yield current_batch

    @classmethod
    def sanitized_value(cls, key):
        """Sanitize a key by replacing non-word characters with '_'

        Args:
            key (str): a string needs to be sanitized

        Returns:
            str: sanitized string
        """
        return re.sub(cls.SPECIAL_CHAR_REGEX, cls.SPECIAL_CHAR_SUB, key)

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
        for key, value in record.items():
            sanitized_key = cls.sanitized_value(key)

            # Handle nested objects
            if isinstance(value, dict):
                new_record[sanitized_key] = cls.sanitize_keys(record[key])
            else:
                new_record[sanitized_key] = record[key]

        return new_record

    @staticmethod
    def _strip_successful_records(batch, response):
        """Inspect the response and remove any records records that have successfully to sent

        For each record, the index of the response element is the same as the index
        used in the request array.

        Args:
            batch (list): List of dicts with JSON dumped records that are being
                sent to Firehose. Format is:
                [{'Data': <json-dumped-rec>}, {'Data': <json-dumped-rec>}]
            response (dict): Response object from the boto3.client.put_record_batch call
                that contains metadata on the success status of the call
        """
        success_indices = [
            idx for idx, rec in enumerate(response['RequestResponses']) if rec.get('RecordId')
        ]

        for idx in sorted(success_indices, reverse=True):
            del batch[idx]

    def _categorize_records(self, payloads):
        """Add the records to the proper list of cached records, based on log type

        Args:
            payloads (list): List of PayloadRecord items that include parsed records
        """
        # Create a dictionary to hold parsed payloads by log type.
        # Firehose needs this information to send to its corresponding
        # delivery stream.
        categorized_records = defaultdict(list)

        for payload in payloads:
            # Only send payloads with enabled log sources
            if not self.enabled_log_source(payload.log_schema_type):
                continue

            # Add the records to the dictionary of categorized records
            categorized_records[payload.log_schema_type].extend(payload.parsed_records)

        return categorized_records

    @classmethod
    def _finalize(cls, response, stream_name, size, function_name):
        """Perform any final operations for this response, such as metric logging, etc

        Args:
            response (dict): boto3 client response object
            stream_name (str): The name of the Delivery Stream to send to
            size (int): The original size of the batch being sent
        """
        if not response:
            return  # Could happen in the case of backoff failing entirely

        # Check for failures that occurred in PutRecordBatch after several backoff attempts
        if response.get('FailedPutCount'):
            failed_records = [
                failed for failed in response['RequestResponses'] if failed.get('ErrorCode')
            ]
            cls._log_failed(response['FailedPutCount'], function_name)

            # Only print the first 100 failed records to Cloudwatch logs
            LOGGER.error('Failed to put the following records to firehose %s: %s', stream_name,
                         json.dumps(failed_records[:1024], indent=2))
            return

        MetricLogger.log_metric(function_name, MetricLogger.FIREHOSE_RECORDS_SENT, size)
        LOGGER.info('Successfully sent %d message(s) to firehose %s with RequestId \'%s\'', size,
                    stream_name,
                    response.get('ResponseMetadata', {}).get('RequestId', ''))

    @classmethod
    def _log_failed(cls, count, function_name):
        """Helper to log the failed Firehose records metric

        Args:
            count (int): Number of failed records
        """
        MetricLogger.log_metric(function_name, MetricLogger.FIREHOSE_FAILED_RECORDS, count)

    def _send_batch(self, stream_name, record_batch, function_name):
        """Send record batches to Firehose

        Args:
            stream_name (str): The name of the Delivery Stream to send to
            record_batch (list): The records to send
        """
        @backoff.on_predicate(backoff.fibo,
                              lambda resp: resp['FailedPutCount'] > 0,
                              max_tries=self.MAX_BACKOFF_ATTEMPTS,
                              max_value=self.MAX_BACKOFF_FIBO_VALUE,
                              on_backoff=backoff_handler(debug_only=False),
                              on_success=success_handler(),
                              on_giveup=giveup_handler())
        @backoff.on_exception(backoff.fibo,
                              self.EXCEPTIONS_TO_BACKOFF,
                              max_tries=self.MAX_BACKOFF_ATTEMPTS,
                              on_backoff=backoff_handler(debug_only=False),
                              on_success=success_handler(),
                              on_giveup=giveup_handler())
        def _firehose_request_helper(data):
            """Firehose request wrapper to use with backoff"""
            # Use the current length of data here so we can track failed records that are retried
            LOGGER.debug('Sending %d records to firehose %s', len(data), stream_name)

            response = self._client.put_record_batch(DeliveryStreamName=stream_name, Records=data)

            # Log this as an error for now so it can be picked up in logs
            if response['FailedPutCount'] > 0:
                LOGGER.warning('Received non-zero FailedPutCount: %d', response['FailedPutCount'])
                # Strip out the successful records so only the failed ones are retried. This happens
                # to the list of dictionary objects, so the called function sees the updated list
                self._strip_successful_records(data, response)

            return response

        # The record here already contains a newline, so do not append one
        records_data = [{'Data': record} for record in record_batch]

        # The try/except here is to catch the raised error at the end of the backoff
        try:
            return _firehose_request_helper(records_data)
        except self.EXCEPTIONS_TO_BACKOFF:
            LOGGER.exception('Firehose request failed')
            # Use the current length of the records_data in case some records were
            # successful but others were not
            self._log_failed(len(records_data), function_name)

    @classmethod
    def generate_firehose_name(cls, prefix, log_stream_name):
        """Generate suffix of stream name complaint to firehose naming restriction, no
        longer than 64 characters

        Args:
            prefix (str): The prefix defined in conf/global.json to firehose stream name
            log_stream_name (str): The name of the log from conf/logs.json or conf/schemas/*.json

        Returns:
            str: suffix of stream name
        """
        if prefix:
            prefix += '_'

        # This same substitution method is used when naming the Delivery Streams
        stream_name = cls.sanitized_value(cls.DEFAULT_FIREHOSE_FMT.format(prefix, log_stream_name))
        if len(stream_name) <= cls.AWS_FIREHOSE_NAME_MAX_LEN:
            return stream_name

        base_name = stream_name[:cls.AWS_FIREHOSE_NAME_MAX_LEN - cls.FIREHOSE_NAME_MIN_HASH_LEN]
        if not base_name.endswith('_'):
            # make sure this ends in an underscore, but not 2
            base_name = f'{base_name[:-1]}_' if base_name[-2] != '_' else f'{base_name[:-2]}_'

        # combine the base_name and first 8 chars of hash result together as new
        # stream name.
        return f'{base_name}{hashlib.md5(stream_name.encode(),usedforsecurity=False).hexdigest()}'[:
                                                                                                   cls
                                                                                                   .
                                                                                                   AWS_FIREHOSE_NAME_MAX_LEN]

    @classmethod
    def artifacts_firehose_stream_name(cls, config):
        """Return Artifacts Firehose Stream Name

        Args:
            config (dict): The loaded config from the 'conf/' directory

        Returns:
            str: Artifacts Firehose Stream Name
        """
        # support custom firehose stream name of Artifacts. User should make sure the length of
        # the custom firehose name is no longer than 64 chars, otherwise the firehose will be
        # failed to create. StreamAlert is not responsible for checking for custom firehose name
        # since it should not change custom settings.
        stream_name = config.get('lambda', {}).get('artifact_extractor_config',
                                                   {}).get('firehose_stream_name')

        return stream_name or cls.generate_firehose_name(
            prefix=config['global']['account']['prefix'], log_stream_name='artifacts')

    @classmethod
    def enabled_log_source(cls, log_source_name):
        """Check that the incoming record is an enabled log source for Firehose

        Args:
            log_source_name (str): The log source of the record

        Returns:
            bool: Whether or not the log source is enabled to send to Firehose
        """
        if not cls._ENABLED_LOGS:
            LOGGER.error('Enabled logs not loaded')
            return False

        return cls.sanitized_value(log_source_name) in cls._ENABLED_LOGS

    @classmethod
    def load_enabled_log_sources(cls, firehose_config, log_sources, force_load=False):
        """Load and expand all declared and enabled Firehose log sources

        Args:
            firehose_config (dict): Loaded Firehose config from global.json
            log_sources (dict): Loaded logs.json file
            force_load (bool=False): Set to True if the log sources should be reloaded
                even if there is cached values

        Returns:
            dict: Enabled logs, key: sanitized table name, value: log type value
        """
        # Do not reload the logs if they are already cached
        if cls._ENABLED_LOGS and not force_load:
            return cls._ENABLED_LOGS

        # Nothing to load if no configs passed
        if not (firehose_config and log_sources):
            return cls._ENABLED_LOGS

        # Expand enabled logs into specific subtypes
        for enabled_log in firehose_config.get('enabled_logs', {}):
            enabled_log_parts = enabled_log.split(':')

            # Expand to all subtypes
            if len(enabled_log_parts) == 1:
                expanded_logs = {
                    cls.sanitized_value(log_name): log_name
                    for log_name in log_sources if log_name.split(':')[0] == enabled_log_parts[0]
                }

                if not expanded_logs:
                    LOGGER.error('Enabled Firehose log %s not declared in logs.json', enabled_log)
                    continue

                cls._ENABLED_LOGS.update(expanded_logs)

            elif len(enabled_log_parts) == 2:
                if enabled_log not in log_sources:
                    LOGGER.error('Enabled Firehose log %s not declared in logs.json', enabled_log)
                    continue

                cls._ENABLED_LOGS[cls.sanitized_value(enabled_log)] = enabled_log

        return cls._ENABLED_LOGS

    @classmethod
    def load_from_config(cls, prefix, firehose_config, log_sources):
        """Get a Firehose client for sending logs

        Args:
            firehose_config (dict): Loaded Firehose config from global.json
            log_sources (dict): Loaded logs.json file

        Returns:
            FirehoseClient or None: If disabled, this returns None, otherwise it returns an
                instanec of FirehoseClient
        """
        if not firehose_config.get('enabled'):
            return
        return cls(prefix=prefix, firehose_config=firehose_config, log_sources=log_sources)

    @classmethod
    def get_client(cls, prefix, artifact_extractor_config):
        """Get a Firehose client for sending artifacts

        Args:
            prefix (str): Account prefix from global.json
            artifact_extractor_config (dict): Loaded Artifact Extractor config from lambda.json

        Returns:
            FirehoseClient or None: If disabled, this returns None, otherwise it returns an
                instanec of FirehoseClient
        """
        if not artifact_extractor_config.get('enabled'):
            return
        return cls(prefix=prefix)

    def send(self, payloads):
        """Send all classified records to a respective Firehose Delivery Stream

        Args:
            payloads (list): List of PayloadRecord items that include parsed records
        """
        categorized_records = self._categorize_records(payloads)

        # Iterate through each set of categorized payloads.
        # Each batch will be processed to their specific Firehose, which lands the data
        # in a specific prefix in S3.
        for log_type, records in categorized_records.items():
            # firehose stream name has the length limit, no longer than 64 characters
            formatted_stream_name = self.generate_firehose_name(self._prefix, log_type)

            # Process each record batch in the categorized payload set
            for record_batch in self._record_batches(records, CLASSIFIER_FUNCTION_NAME):
                batch_size = len(record_batch)
                response = self._send_batch(formatted_stream_name, record_batch,
                                            CLASSIFIER_FUNCTION_NAME)

                self._finalize(response, formatted_stream_name, batch_size,
                               CLASSIFIER_FUNCTION_NAME)

        # return categorized records for extracting artifacts if the feature is enabled
        return categorized_records

    def send_artifacts(self, artifacts, stream_name):
        """Send artifacts to artifacts Firehose delievery stream
        Args:
            artifacts (list(dict)): A list of artifacts extracted from normalized records.
            stream_name (str): Stream name of destination Firehose.
        """
        for artifact_batch in self._record_batches(artifacts, CLASSIFIER_FUNCTION_NAME):
            batch_size = len(artifact_batch)
            response = self._send_batch(stream_name, artifact_batch, CLASSIFIER_FUNCTION_NAME)
            self._finalize(response, stream_name, batch_size, CLASSIFIER_FUNCTION_NAME)

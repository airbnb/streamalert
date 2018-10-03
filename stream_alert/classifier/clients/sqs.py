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
import json
import os

import backoff
import boto3
from botocore.exceptions import ClientError

from stream_alert.shared import CLASSIFIER_FUNCTION_NAME as FUNCTION_NAME
from stream_alert.shared.helpers import boto
from stream_alert.shared.logger import get_logger
from stream_alert.shared.metrics import MetricLogger
from stream_alert.shared.backoff_handlers import (
    backoff_handler,
    giveup_handler,
    success_handler
)

LOGGER = get_logger(__name__)


class SQSClientError(Exception):
    """Exception to be used for any SQSClient errors"""


class SQSClient(object):
    """SQSClient for sending batches of classified records to the Rules Engine function"""
    # Exception for which backoff operations should be performed
    EXCEPTIONS_TO_BACKOFF = (ClientError,)

    # Maximum amount of times to retry with backoff
    MAX_BACKOFF_ATTEMPTS = 5
    MAX_BACKOFF_FIBO_VALUE = 8

    # SQS limitations
    MAX_BATCH_COUNT = 10
    MAX_BATCH_SIZE = 256 * 1024  # 256 KB

    _queue = None

    def __init__(self):
        queue_url = os.environ.get('SQS_QUEUE_URL', '')
        if not queue_url:
            raise SQSClientError('No queue URL found in environment variables')

        # Only recreate the queue resource if it's not already cached
        SQSClient._queue = (
            SQSClient._queue or
            boto3.resource('sqs', config=boto.default_config()).Queue(queue_url)
        )

    @property
    def queue(self):
        return SQSClient._queue

    @classmethod
    def _log_failed(cls, count):
        """Helper to log the failed SQS records metric

        Args:
            count (int): Number of failed records
        """
        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.SQS_FAILED_RECORDS, count)

    @classmethod
    def _message_batches(cls, records):
        """Segment the records into batches that conform to SQS restrictions

        This will log any single record that is too large to send, and skip it.

        Args:
            records (list): The original records list to be segmented

        Yields:
            list: Batches of JSON serialized records that conform to SQS restrictions
        """
        # Dump the records to a list of minimal json
        records_json = [
            json.dumps(record, separators=(',', ':')) for record in records
        ]

        current_batch_size = 0
        current_batch = []
        for record in records_json:
            line_len = len(record)
            # Check if the max size of the batch has been reached or if the current
            # record will exceed the max batch size and start a new batch
            if ((len(current_batch) == cls.MAX_BATCH_COUNT) or
                    (current_batch_size + line_len > cls.MAX_BATCH_SIZE)):
                yield current_batch[:]
                current_batch_size = 0
                del current_batch[:]

            if line_len > cls.MAX_BATCH_SIZE:
                LOGGER.error('Record too large (%d) to send to SQS:\n%s', line_len, record)
                cls._log_failed(1)
                continue

            # Add the record to the batch
            current_batch_size += line_len
            current_batch.append(record)

        # yield the result of the last batch (no need to copy via slicing)
        if current_batch:
            yield current_batch

    @classmethod
    def _format_failure_message(cls, failure, record=None):
        message = (
            'Record failed to send to SQS. ID: {Id}, SenderFault: {SenderFault}, '
            'Code: {Code}, Error: {Message}'.format(
                **failure
            )
        )

        if record:
            message = '{base_message}, Record:\n{record}'.format(
                base_message=message,
                record=record
            )

        return message

    def _finalize(self, response, batch):
        """Perform any final operations for this response, such as metric logging, etc

        Args:
            batch (list): List of JSON records that are being sent to SQS
            response (dict): boto3 client response object
            size (int): The original size of the batch being sent
        """
        if not response:
            return  # Could happen in the case of backoff failing enitrely

        # Check for failures that occurred in PutRecordBatch after several backoff attempts
        # And log the actual record from the batch
        failed = self._check_failures(response, batch=batch)

        # Remove the failed messages in this batch for an accurate metric
        successful_records = len(batch) - failed

        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.SQS_RECORDS_SENT, successful_records)
        LOGGER.info('Successfully sent %d messages to SQS Queue: %s',
                    successful_records, self.queue.url)

    @staticmethod
    def _strip_successful_records(messages, response):
        """Inspect the response and remove any records records that have successfully to sent

        For each record, the index of the response element is the same as the index
        used in the request array.

        Args:
            batch (list): List of dicts with JSON dumped records as MessageBody that are being
                sent to SQS. Format is:
                [{'Id': '...', 'MessageBody': '...'}, {'Id': '...', 'MessageBody': '...'}]
            response (dict): Response object from the boto3.resource.send_messages call
                that contains metadata on the success status of the call
        """
        success_indices = [
            int(item['Id']) for item in response['Successful']
        ]

        LOGGER.info('Removing sucessful message indices from batch: %s', success_indices)

        for idx in sorted(success_indices, reverse=True):
            del messages[idx]

    def _check_failures(self, response, batch=None):
        """Inspect the response to see if the failure was our fault (the Sender)

        Args:
            response (dict): Response object from the boto3.resource.send_messages call
                that contains metadata on the success status of the call
            batch (list): List of dicts with JSON dumped records as MessageBody that are being
                sent to SQS. Format is:
                [{'Id': '...', 'MessageBody': '...'}, {'Id': '...', 'MessageBody': '...'}]
        Raises:
            SQSClientError: Indication that there is something wrong with the sender configuration
        """
        if not response.get('Failed'):
            return 0  # nothing to do here

        LOGGER.error('The following records failed to put to the SQS Queue: %s',
                     self.queue.url)

        for failure in response['Failed']:
            record = batch[int(failure['Id'])] if batch else None
            LOGGER.error(self._format_failure_message(failure, record=record))

        failed = len(response.get('Failed', []))
        self._log_failed(failed)

        # Raise an exception if this is the fault of the sender (us)
        if any(result['SenderFault'] for result in response['Failed']):
            raise SQSClientError('Failed to send records to SQS:\n{}'.format(response))

        return failed

    def _send_messages(self, batched_messages):
        """Send new formatted messages to CSIRT SQS
        Args:
            batched_messages (list): A list of messages that are already serialized to json
                to be sent to the Rules Engine function
        Returns:
            bool: True if the request was successful, False otherwise
        """
        @backoff.on_predicate(backoff.fibo,
                              lambda resp: len(resp.get('Failed', [])) > 0,
                              max_tries=self.MAX_BACKOFF_ATTEMPTS,
                              max_value=self.MAX_BACKOFF_FIBO_VALUE,
                              jitter=backoff.full_jitter,
                              on_backoff=backoff_handler(debug_only=False),
                              on_success=success_handler(),
                              on_giveup=giveup_handler())
        @backoff.on_exception(backoff.expo, self.EXCEPTIONS_TO_BACKOFF,
                              max_tries=self.MAX_BACKOFF_ATTEMPTS,
                              on_backoff=backoff_handler(debug_only=False),
                              on_success=success_handler(),
                              on_giveup=giveup_handler())
        def _send_messages_helper(entries):
            """Inner helper function for sending messages with backoff_handler

            Args:
                entries (list<dict>): List of SQS SendMessageBatchRequestEntry items
            """
            LOGGER.info('Sending %d messages to %s', len(entries), self.queue.url)

            response = self.queue.send_messages(Entries=entries)

            LOGGER.info('Response from SQS: \n%s', response)

            if response.get('Failed'):
                self._check_failures(response)  # Raise an exception if this is our fault
                self._strip_successful_records(entries, response)

            return response

        message_entries = [
            {
                'Id': str(idx),
                'MessageBody': message
            } for idx, message in enumerate(batched_messages)
        ]

        _send_messages_helper(message_entries)

    @staticmethod
    def _payload_messages(payloads):
        """Prepare a list of all records from the payload to send to SQS

        Args:
            payloads (list): List of PayloadRecord items that include parsed records

        Returns:
            list<dict>: All messages formatted for ingestion by the Rules Engine function
        """
        return [
            message for message in payload.sqs_messages
            for payload in payloads
        ]

    def send(self, payloads):
        """Send a list of records to SQS, batching as necessary

        Args:
            records (list): Records to be sent to SQS for consumption by the rules engine

        Raises:
            SQSClientError: Exception if something went wrong during sending messages to SQS
        """
        records = self._payload_messages(payloads)

        # SQS only supports up to 10 messages so do the send in batches
        for message_batch in self._message_batches(records):
            response = self._send_messages(message_batch)
            self._finalize(response, message_batch)

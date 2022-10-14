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
import json
import os

import backoff
import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import ConnectionError as BotocoreConnectionError
from botocore.exceptions import HTTPClientError

from streamalert.shared import CLASSIFIER_FUNCTION_NAME as FUNCTION_NAME
from streamalert.shared.backoff_handlers import (backoff_handler,
                                                 giveup_handler,
                                                 success_handler)
from streamalert.shared.helpers import boto
from streamalert.shared.logger import get_logger
from streamalert.shared.metrics import MetricLogger

LOGGER = get_logger(__name__)


class SQSClientError(Exception):
    """Exception to be used for any SQSClient errors"""


class SQSClient:
    """SQSClient for sending batches of classified records to the Rules Engine function"""
    # Exception for which backoff operations should be performed
    EXCEPTIONS_TO_BACKOFF = (ClientError, BotocoreConnectionError, HTTPClientError)

    # Maximum amount of times to retry with backoff
    MAX_BACKOFF_ATTEMPTS = 5

    # SQS limitations
    MAX_SIZE = 256 * 1024  # 256 KB

    _queue = None

    def __init__(self):
        if queue_url := os.environ.get('SQS_QUEUE_URL', ''):
            # Only recreate the queue resource if it's not already cached
            SQSClient._queue = (SQSClient._queue or boto3.resource(
                'sqs', config=boto.default_config()).Queue(queue_url))
        else:
            raise SQSClientError('No queue URL found in environment variables')

    @property
    def queue(self):
        return SQSClient._queue

    @classmethod
    def _segment_records(cls, records):

        batch_size = 2  # for [] chars on array
        batch = []
        record_count = len(records)
        for idx, record in enumerate(records, start=1):
            # for , between records
            size = len(record) + (1 if idx != record_count and batch else 0)
            if size + 2 > cls.MAX_SIZE:
                LOGGER.error('Record is too large to send to SQS:\n%s', record)
                MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.SQS_FAILED_RECORDS, 1)
                continue

            if idx == record_count:
                if size + batch_size >= cls.MAX_SIZE:
                    yield batch[:], len(batch)

                if size + batch_size < cls.MAX_SIZE:  # this record fits on current batch
                    batch.append(record)
                    yield batch[:], len(batch)
                else:
                    yield [record], 1
                return

            if size + batch_size >= cls.MAX_SIZE:
                yield batch[:], len(batch)

                del batch[:]
                batch_size = 2

            batch.append(record)
            batch_size += size

    def _finalize(self, response, count):
        """Perform any final operations for this response, such as metric logging, etc

        Args:
            response (string|bool): MessageId or False if this request failed
            count (int): The size of the batch being sent to be logged as successful or failed
        """
        if not response:  # Could happen in the case of backoff failing entirely
            MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.SQS_FAILED_RECORDS, count)
            return

        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.SQS_RECORDS_SENT, count)

        LOGGER.debug('Successfully sent message with %d records to %s with MessageId %s', count,
                     self.queue.url, response)

    def _send_message(self, records):
        """Send a single message with a blob of records to CSIRT SQS
        Args:
            message (string): A message that is serialized to json to be sent to
                the Rules Engine function

        Returns:
            string|bool: The MessageId if the request was successful, False otherwise
        """
        @backoff.on_exception(backoff.expo,
                              self.EXCEPTIONS_TO_BACKOFF,
                              max_tries=self.MAX_BACKOFF_ATTEMPTS,
                              on_backoff=backoff_handler(debug_only=False),
                              on_success=success_handler(),
                              on_giveup=giveup_handler())
        def _send_message_helper(request):
            """Inner helper function for sending a single message with backoff

            Args:
                entries (list<dict>): List of SQS SendMessageBatchRequestEntry items
            """
            return self.queue.send_message(**request)

        # Prepare the request now to save time during retries
        request = {'MessageBody': '[{}]'.format(','.join(records))}

        # The try/except here is to catch any raised errors at the end of the backoff
        try:
            response = _send_message_helper(request)
            return response['MessageId']
        except self.EXCEPTIONS_TO_BACKOFF:
            LOGGER.exception('SQS request failed')
            return False

    @staticmethod
    def _payload_messages(payloads):
        """Prepare a list of all records from the payload to send to SQS

        Args:
            payloads (list): List of PayloadRecord items that include parsed records

        Returns:
            list<dict>: All messages formatted for ingestion by the Rules Engine function
        """
        return [
            json.dumps(message, separators=(',', ':')) for payload in payloads
            for message in payload.sqs_messages
        ]

    def send(self, payloads):
        """Send a list of records from payloads to SQS, segmenting as necessary

        Args:
            payloads (list): Payloads containing records to be sent to SQS for
                consumption by the rules engine

        Raises:
            SQSClientError: Exception if something went wrong during sending messages to SQS
        """
        records = self._payload_messages(payloads)
        for records, count in self._segment_records(records):
            LOGGER.info('Sending %d record(s) to %s', count, self.queue.url)
            response = self._send_message(records)
            self._finalize(response, count)

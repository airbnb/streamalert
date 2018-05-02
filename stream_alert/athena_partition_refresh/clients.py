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
import urllib

import backoff
import boto3

from stream_alert.athena_partition_refresh import LOGGER
from stream_alert.shared.backoff_handlers import (
    backoff_handler,
    giveup_handler,
    success_handler
)


class StreamAlertSQSClient(object):
    """A StreamAlert SQS Client for polling and deleting S3 event notifications

    Attributes:
        config: The loaded StreamAlert configuration
        sqs_client: The Boto3 SQS client
        athena_sqs_url: The URL to the Athena SQS Queue
        received_messages: A list of receieved SQS messages
        processed_messages: A list of processed SQS messages
    """
    DEFAULT_QUEUE_NAME = '{}_streamalert_athena_s3_notifications'
    MAX_SQS_GET_MESSAGE_COUNT = 10
    SQS_BACKOFF_MAX_RETRIES = 10

    def __init__(self, config):
        """Initialize the StreamAlertSQS Client

        Args:
            config (CLIConfig): Loaded StreamAlert configuration
        """
        self.config = config
        self.received_messages = []
        self.processed_messages = []
        self.deleted_message_count = 0
        self.sqs_client = boto3.client('sqs')
        self.athena_sqs_url = self.sqs_client.get_queue_url(QueueName=self.queue_name)['QueueUrl']

    @property
    def queue_name(self):
        """Return the name of the sqs queue to use. This can be overridden in the config"""
        prefix = self.config['global']['account']['prefix']
        queue = self.config['lambda']['athena_partition_refresh_config'].get(
            'queue_name',
            self.DEFAULT_QUEUE_NAME.format(prefix)
        )

        return queue.replace(' ', '') # strip any spaces which are invalid queue names

    def get_messages(self, max_tries=5, max_value=5, max_messages=MAX_SQS_GET_MESSAGE_COUNT):
        """Poll the SQS queue for new messages

        Keyword Args:
            max_tries (int): The number of times to backoff
                Backoff up to 5 times to limit the time spent in this operation
                relative to the entire Lambda duration.
            max_value (int): The max wait interval between backoffs
                This value restricts the max time of backoff each try.
                This means the total backoff time for one function call is:
                    max_tries (attempts) * max_value (seconds)
            max_messages (int): The max number of messages to get from SQS
        """
        start_message_count = len(self.received_messages)

        # Number of messages to poll from the stream.
        if max_messages > self.MAX_SQS_GET_MESSAGE_COUNT:
            LOGGER.error('The maximum requested messages exceeds the SQS limitation per request. '
                         'Setting max messages to %d', self.MAX_SQS_GET_MESSAGE_COUNT)
            max_messages = self.MAX_SQS_GET_MESSAGE_COUNT

        @backoff.on_predicate(backoff.fibo,
                              max_tries=max_tries,
                              max_value=max_value,
                              jitter=backoff.full_jitter,
                              on_backoff=backoff_handler(),
                              on_success=success_handler(True),
                              on_giveup=giveup_handler(True))
        def _receive_messages():
            polled_messages = self.sqs_client.receive_message(
                QueueUrl=self.athena_sqs_url,
                MaxNumberOfMessages=max_messages
            )
            if 'Messages' not in polled_messages:
                return True # return True to stop polling

            self.received_messages.extend(polled_messages['Messages'])

        _receive_messages()
        batch_count = len(self.received_messages) - start_message_count
        LOGGER.info('Received %d message(s) from SQS', batch_count)

    def delete_messages(self):
        """Delete messages off the queue once processed"""
        if not self.processed_messages:
            LOGGER.error('No processed messages to delete')
            return
        @backoff.on_predicate(backoff.fibo,
                              lambda len_messages: len_messages > 0,
                              max_value=10,
                              max_tries=self.SQS_BACKOFF_MAX_RETRIES,
                              jitter=backoff.full_jitter,
                              on_backoff=backoff_handler(),
                              on_success=success_handler())
        def _delete_messages_from_queue():
            # Determine the message batch for SQS message deletion
            len_processed_messages = len(self.processed_messages)
            batch = len_processed_messages if len_processed_messages < 10 else 10
            # Pop processed records from the list to be deleted
            message_batch = [self.processed_messages.pop() for _ in range(batch)]

            # Try to delete the batch
            resp = self.sqs_client.delete_message_batch(
                QueueUrl=self.athena_sqs_url,
                Entries=[{'Id': message['MessageId'],
                          'ReceiptHandle': message['ReceiptHandle']}
                         for message in message_batch])

            # Handle successful deletions
            if resp.get('Successful'):
                self.deleted_message_count += len(resp['Successful'])
            # Handle failure deletion
            if resp.get('Failed'):
                LOGGER.error(('Failed to delete the messages with following (%d) '
                              'error messages:\n%s'),
                             len(resp['Failed']), json.dumps(resp['Failed']))
                # Add the failed messages back to the processed_messages attribute
                # to be retried via backoff
                failed_message_ids = [message['Id'] for message in resp['Failed']]
                push_bach_messages = [message for message in message_batch
                                      if message['MessageId'] in failed_message_ids]

                self.processed_messages.extend(push_bach_messages)

            return len(self.processed_messages)

        _delete_messages_from_queue()

    def unique_s3_buckets_and_keys(self):
        """Filter a list of unique s3 buckets and S3 keys from event notifications

        Returns:
            (dict): Keys of bucket names, and values of unique S3 keys
        """
        s3_buckets_and_keys = defaultdict(set)

        if not self.received_messages:
            LOGGER.error('No messages to filter, fetch the messages with get_messages()')
            return

        for message in self.received_messages:
            if 'Body' not in message:
                LOGGER.error('Missing \'Body\' key in SQS message, skipping')
                continue

            loaded_message = json.loads(message['Body'])

            # From AWS documentation: http://amzn.to/2w4fcSq
            # When you configure an event notification on a bucket,
            # Amazon S3 sends the following test message:
            # {
            #    "Service":"Amazon S3",
            #    "Event":"s3:TestEvent",
            #    "Time":"2014-10-13T15:57:02.089Z",
            #    "Bucket":"bucketname",
            #    "RequestId":"5582815E1AEA5ADF",
            #    "HostId":"8cLeGAmw098X5cv4Zkwcmo8vvZa3eH3eKxsPzbB9wrR+YstdA6Knx4Ip8EXAMPLE"
            # }
            if loaded_message.get('Event') == 's3:TestEvent':
                LOGGER.debug('Skipping S3 bucket notification test event')
                continue

            if 'Records' not in loaded_message:
                LOGGER.error('Missing \'Records\' key in SQS message, skipping:\n%s',
                             json.dumps(loaded_message, indent=4))
                continue

            for record in loaded_message['Records']:
                if 's3' not in record:
                    LOGGER.info('Skipping non-s3 bucket notification message')
                    LOGGER.debug(record)
                    continue

                bucket_name = record['s3']['bucket']['name']
                # Account for special characters in the S3 object key
                # Example: Usage of '=' in the key name
                object_key = urllib.unquote(record['s3']['object']['key']).decode('utf8')
                s3_buckets_and_keys[bucket_name].add(object_key)

                # Add to a new list to track successfully processed messages from the queue
                self.processed_messages.append(message)

        return s3_buckets_and_keys

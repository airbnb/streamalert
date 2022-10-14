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
import math

import boto3
from botocore.exceptions import ClientError

from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


class Batcher:
    """Batcher class to handle segmenting large messages going to the classifier lambda function"""
    # Max lambda input payload size is 128K for the 'event' invocation type
    MAX_LAMBDA_PAYLOAD_SIZE = 128 * 1000
    LAMBDA_CLIENT = None

    def __init__(self, source_func, destination_func):
        # Create the lambda client if it does not exist
        if Batcher.LAMBDA_CLIENT is None:
            Batcher.LAMBDA_CLIENT = boto3.client('lambda')
        self._source_function = source_func
        # The classifier function name will look like:
        # <prefix>_<cluster>_streamalert_classifier
        self._destination_function = destination_func

    def send_logs(self, logs):
        """Public method to send the logs to the classifier function

        Args:
            source_function (str): The app function name from which the logs came
            logs (list): List of the logs that have been gathered
        """
        LOGGER.info('Starting batch send of %d logs to the classifier function', len(logs))

        # Try to send all of the logs in one fell swoop
        if self._send_logs_to_lambda(logs):
            return

        # Fall back on segmenting the list of logs into multiple requests
        # if they could not be sent at once
        self._segment_and_send(logs)

        LOGGER.info('Finished batch send of %d logs to the classifier function', len(logs))

    def _segment_and_send(self, logs):
        """Protected method for segmenting a list of logs into smaller lists
        so they conform to the input limit of AWS Lambda

        Args:
            source_function (str): The app function name from which the logs came
            logs (list): List of the logs that have been gathered
        """
        log_count = len(logs)
        LOGGER.debug('Segmenting %d logs into subsets', log_count)

        segment_size = int(math.ceil(log_count / 2.0))
        for index in range(0, log_count, segment_size):
            subset = logs[index:segment_size + index]
            # Try to send this current subset to the classifier function
            # and segment again if they are too large to be sent at once
            if not self._send_logs_to_lambda(subset):
                self._segment_and_send(subset)

        return True

    def _send_logs_to_lambda(self, logs):
        """Protected method for sending logs to the classifier lambda
        function for processing. This performs some size checks before sending.

        Args:
            source_function (str): The app function name from which the logs came
            logs (list): List of the logs that have been gathered
        """
        # Create a payload to be sent to the classifier function that contains the
        # service these logs were collected from and the list of logs
        payload = {'Records': [{'streamalert_app': self._source_function, 'logs': logs}]}
        payload_json = json.dumps(payload, separators=(',', ':'))
        if len(payload_json) > self.MAX_LAMBDA_PAYLOAD_SIZE:
            if len(logs) == 1:
                LOGGER.error(
                    'Log payload size for single log exceeds input limit and will be '
                    'dropped (%d > %d max).', len(payload_json), self.MAX_LAMBDA_PAYLOAD_SIZE)
                return True

            LOGGER.debug(
                'Log payload size for %d logs exceeds limit and will be '
                'segmented (%d > %d max).', len(logs), len(payload_json),
                self.MAX_LAMBDA_PAYLOAD_SIZE)
            return False

        LOGGER.debug('Sending %d logs to classifier function with payload size %d', len(logs),
                     len(payload_json))

        try:
            response = Batcher.LAMBDA_CLIENT.invoke(FunctionName=self._destination_function,
                                                    InvocationType='Event',
                                                    Payload=payload_json,
                                                    Qualifier='production')

        except ClientError as err:
            LOGGER.error(
                'An error occurred while sending logs to '
                '\'%s:production\'. Error is: %s', self._destination_function, err.response)
            raise

        LOGGER.info('Sent %d logs to \'%s\' with Lambda request ID \'%s\'', len(logs),
                    self._destination_function, response['ResponseMetadata']['RequestId'])

        return True

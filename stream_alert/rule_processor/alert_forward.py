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
from datetime import datetime
import json
import os
import time

import backoff
import boto3
from botocore.exceptions import ClientError

from stream_alert.shared import backoff_handlers
from stream_alert.rule_processor import LOGGER


class AlertForwarder(object):
    """Sends alerts to the Alert Processor and the alerts Dynamo table."""
    # TODO: Do not send to Alert Processor after Alert Merger is implemented
    BACKOFF_MAX_RETRIES = 6

    def __init__(self, env):
        """Initialize the Forwarder with the boto3 clients and resource names.

        Args:
            env (dict): loaded dictionary containing environment information
        """
        self.env = env
        self.client_dynamo = boto3.client('dynamodb', region_name=self.env['lambda_region'])
        self.client_lambda = boto3.client('lambda', region_name=self.env['lambda_region'])
        self.function = os.environ['ALERT_PROCESSOR']
        self.table = os.environ['ALERT_TABLE']

        # Keep track of unprocessed items when retrying batch_write_item()
        self.unprocessed_items = None

    def _send_to_lambda(self, alerts):
        """DEPRECATED: Invoke Alert Processor directly

        Sends a message to the alert processor with the following JSON format:
            {
                "record": record,
                "metadata": {
                    "rule_name": rule.rule_name,
                    "rule_description": rule.rule_function.__doc__,
                    "log": str(payload.log_source),
                    "outputs": rule.outputs,
                    "type": payload.type,
                    "source": {
                        "service": payload.service,
                        "entity": payload.entity
                    }
                }
            }
        """
        for alert in alerts:
            try:
                data = json.dumps(alert, default=lambda o: o.__dict__)
            except AttributeError as err:
                LOGGER.error('An error occurred while dumping alert to JSON: %s '
                             'Alert: %s',
                             err.message,
                             alert)
                continue

            try:
                response = self.client_lambda.invoke(
                    FunctionName=self.function,
                    InvocationType='Event',
                    Payload=data,
                    Qualifier='production'
                )

            except ClientError as err:
                LOGGER.exception('An error occurred while sending alert to '
                                 '\'%s:production\'. Error is: %s. Alert: %s',
                                 self.function,
                                 err.response,
                                 data)
                continue

            if response['ResponseMetadata']['HTTPStatusCode'] != 202:
                LOGGER.error('Failed to send alert to \'%s\': %s',
                             self.function, data)
                continue

            if self.env['lambda_alias'] != 'development':
                LOGGER.info('Sent alert to \'%s\' with Lambda request ID \'%s\'',
                            self.function,
                            response['ResponseMetadata']['RequestId'])

    def _alert_batches(self, alerts, batch_size=25):
        """Group alerts into batches of 25, the maximum allowed by Dynamo batch_write_item.

        Yields:
            (dict) The constructed request for batch_write_item, containing <= 25 alerts.
                Maps table name to a list of requests.
        """
        for i in range(0, len(alerts), batch_size):
            batch = alerts[i:i+batch_size]
            yield {
                self.table: [
                    {
                        'PutRequest': {
                            'Item': {
                                'RuleName': {'S': alert['rule_name']},
                                'Timestamp': {
                                    # ISO 8601 datetime format, and is unique for each alert
                                    'S': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                                },
                                'Cluster': {'S': os.environ['CLUSTER']},
                                'RuleDescription': {'S': alert['rule_description']},
                                'Outputs': {'SS': alert['outputs']},
                                # Compact JSON encoding (no extra spaces)
                                'Record': {'S': json.dumps(alert['record'], separators=(',', ':'))},
                                # TODO: Remove TTL after alert merger is implemented
                                'TTL': {'N': str(int(time.time()) + 7200)}  # 2 hour TTL
                            }
                        }
                    }
                    for alert in batch
                ]
            }

    def _batch_write(self):
        """Write a batch of alerts to Dynamo, retrying with exponential backoff for failed items.

        Returns:
            (bool) True if *all* items were written successfully, False otherwise.
        """
        @backoff.on_predicate(backoff.expo,
                              max_tries=self.BACKOFF_MAX_RETRIES, jitter=backoff.full_jitter,
                              on_backoff=backoff_handlers.backoff_handler,
                              on_success=backoff_handlers.success_handler,
                              on_giveup=backoff_handlers.giveup_handler)
        @backoff.on_exception(backoff.expo, ClientError,
                              max_tries=self.BACKOFF_MAX_RETRIES, jitter=backoff.full_jitter,
                              on_backoff=backoff_handlers.backoff_handler,
                              on_success=backoff_handlers.success_handler,
                              on_giveup=backoff_handlers.giveup_handler)
        def decorated_batch_write(cls):
            """batch_write_item with the unprocessed_items from the AlertForwarder instance.

            There are 2 different errors to handle here:
                (1) If Dynamo is unresponsive, a boto ClientError will be raised.
                (2) The batch_write_item operation can fail halfway through, in which case the
                    unprocessed items are returned in the response. In this case, unprocessed items
                    are stored in the class instance, and we return False.
                    The backoff.on_predicate will automatically retry with any Falsey value, and
                    batch_write will run again, but only with the remaining unprocessed items.

            Args:
                cls (AlertForwarder): Instance of the AlertForwarder

            Returns:
                (bool) True if the batch write succeeded, False if there were UnprocessedItems.
            """
            response = cls.client_dynamo.batch_write_item(RequestItems=cls.unprocessed_items)
            cls.unprocessed_items = response['UnprocessedItems']
            return len(cls.unprocessed_items) == 0

        return decorated_batch_write(self)

    def _send_to_dynamo(self, alerts):
        """Write alerts in batches to Dynamo."""
        for batch_num, batch in enumerate(self._alert_batches(alerts), start=1):
            LOGGER.info('Sending batch %d to Dynamo with %d alert(s)',
                        batch_num, len(batch[self.table]))
            self.unprocessed_items = batch
            if not self._batch_write():
                LOGGER.error('Unable to save alert batch; unprocessed items remain: %s',
                             json.dumps(self.unprocessed_items))

    def send_alerts(self, alerts):
        """Send alerts to the Alert Processor and to the alerts Dynamo table.

        Args:
            alerts (list): A list of dictionaries representing json alerts.
        """
        self._send_to_lambda(alerts)

        # For now, don't blow up the rule processor if there is a problem sending to Dynamo.
        # TODO: Remove/refine broad exception handling once tested.
        try:
            self._send_to_dynamo(alerts)
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception('Error saving alerts to Dynamo')

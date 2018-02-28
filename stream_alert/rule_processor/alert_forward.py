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
        for i in xrange(0, len(alerts), batch_size):
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
                                'Record': {'S': json.dumps(alert['record'], separators=(',', ':'))}
                            }
                        }
                    }
                    for alert in batch
                ]
            }

    @backoff.on_exception(backoff.expo, ClientError, max_tries=5, jitter=backoff.full_jitter,
                          on_backoff=backoff_handlers.backoff_handler,
                          on_success=backoff_handlers.success_handler,
                          on_giveup=backoff_handlers.giveup_handler)
    def _batch_write(self, request_items, max_attempts=5):
        """Write a batch of alerts to Dynamo, retrying with exponential backoff for failed items.

        Args:
            request_items (dict): The generated RequestItems dict from _alert_batches().
            max_attempts (int): Maximum number of times to retry UnprocessedItems.

        Returns:
            (bool) True if the batch write was eventually successful, False otherwise.
        """
        for attempt in xrange(1, max_attempts + 1):
            response = self.client_dynamo.batch_write_item(RequestItems=request_items)

            # If Dynamo experiences an internal error, unprocessed items are listed in the response.
            # AWS recommends retrying unprocessed items in a loop with exponential backoff.
            request_items = response['UnprocessedItems']
            if request_items:
                LOGGER.warn(
                    'Batch write failed: %d alerts were not written (attempt %d/%d)',
                    len(request_items[self.table]), attempt, max_attempts)
                # Simple exponential backoff: Sleep 0.5, 1, 2, 4 and 8 seconds.
                time.sleep(0.25 * 2 ** attempt)
                attempt += 1
            else:
                return True

        return False

    def _send_to_dynamo(self, alerts):
        """Write alerts in batches to Dynamo."""
        for batch_num, batch in enumerate(self._alert_batches(alerts), start=1):
            LOGGER.info('Sending batch #%d to Dynamo with %d alert(s)',
                        batch_num, len(batch[self.table]))
            if not self._batch_write(batch):
                LOGGER.error('Unable to save alert batch %s', json.dumps(batch))

    def send_alerts(self, alerts):
        """Send alerts to the Alert Processor and to the alerts Dynamo table.

        Args:
            alerts (list): A list of dictionaries representing json alerts.
        """
        self._send_to_lambda(alerts)

        # While we are testing this, exceptions should be logged but not raise errors.
        try:
            self._send_to_dynamo(alerts)
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception('Error saving alerts to Dynamo')

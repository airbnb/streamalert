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

import boto3
from botocore.exceptions import ClientError

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
        self.table = boto3.resource(
            'dynamodb', region_name=env['lambda_region']).Table(os.environ['ALERTS_TABLE'])
        self.client_lambda = boto3.client('lambda', region_name=self.env['lambda_region'])
        self.function = os.environ['ALERT_PROCESSOR']

        # Keep track of unprocessed items when retrying batch_write_item()
        self.unprocessed_items = None

    def _send_to_lambda(self, alerts):
        """Invoke Alert Processor directly

        Sends a message to the alert processor with the following JSON format:
            {
                'record': record,
                'rule_name': rule.rule_name,
                'rule_description': rule.rule_function.__doc__ or DEFAULT_RULE_DESCRIPTION,
                'log_source': str(payload.log_source),
                'log_type': payload.type,
                'outputs': rule.outputs,
                'source_service': payload.service(),
                'source_entity': payload.entity,
                'context': rule.context
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

    @staticmethod
    def dynamo_record(alert):
        """Convert an alert (dict) into a Dynamo item (dict)."""
        return {
            'RuleName': alert['rule_name'],
            'AlertID': alert['id'],
            # ISO 8601 datetime format
            'Created': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            'Cluster': os.environ['CLUSTER'],
            'LogSource': alert['log_source'],
            'LogType': alert['log_type'],
            'RuleDescription': alert['rule_description'],
            'SourceEntity': alert['source_entity'],
            'SourceService': alert['source_service'],
            'Outputs': set(alert['outputs']),
            # Compact JSON encoding (no extra spaces)
            'Record': json.dumps(alert['record'], separators=(',', ':')),
            # TODO: Remove TTL after alert merger is implemented
            'TTL': int(time.time()) + 7200  # 2 hour TTL
        }

    def _send_to_dynamo(self, alerts):
        """Write alerts in batches to Dynamo."""
        # The batch_writer() automatically handles buffering, batching, and retrying failed items
        with self.table.batch_writer() as batch:
            for alert in alerts:
                batch.put_item(Item=self.dynamo_record(alert))
        LOGGER.info('Successfully sent %d alerts to dynamo:%s', len(alerts), self.table.table_name)

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

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

import boto3
from botocore.exceptions import ClientError

from stream_alert.shared.metrics import MetricLogger
from stream_alert.rule_processor import FUNCTION_NAME, LOGGER


class AlertForwarder(object):
    """Sends alerts to the Alert Processor and the alerts Dynamo table."""

    def __init__(self, env):
        """Initialize the Forwarder with the boto3 clients and resource names.

        Args:
            env (dict): loaded dictionary containing environment information
        """
        self.table = boto3.resource(
            'dynamodb', region_name=env['lambda_region']).Table(os.environ['ALERTS_TABLE'])

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
            'Record': json.dumps(alert['record'], separators=(',', ':'))
        }

    def _send_to_dynamo(self, alerts):
        """Write alerts in batches to Dynamo."""
        # The batch_writer() automatically handles buffering, batching, and retrying failed items
        with self.table.batch_writer() as batch:
            for alert in alerts:
                batch.put_item(Item=self.dynamo_record(alert))
        LOGGER.info(
            'Successfully sent %d alert(s) to dynamo:%s', len(alerts), self.table.table_name)

    def send_alerts(self, alerts):
        """Send alerts to the Alert Processor and to the alerts Dynamo table.

        Args:
            alerts (list): A list of dictionaries representing json alerts.
        """
        try:
            self._send_to_dynamo(alerts)
        except ClientError:
            # The batch_writer() automatically retries transient errors - any raised ClientError
            # is likely unrecoverable. Log an exception and metric
            LOGGER.exception('Error saving alerts to Dynamo')
            MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.FAILED_DYNAMO_WRITES, 1)

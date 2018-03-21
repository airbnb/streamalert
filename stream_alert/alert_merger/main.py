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
from __future__ import absolute_import
from decimal import Decimal
import json
import os
import time

from stream_alert.alert_merger import LOGGER
from stream_alert.shared.metrics import ALERT_MERGER_NAME, MetricLogger

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError


class AlertTable(object):
    """Provides convenience methods for accessing and modifying the alerts table."""

    def __init__(self, table_name):
        self.table = boto3.resource('dynamodb').Table(table_name)

    @staticmethod
    def _paginate(func, func_kwargs):
        """Paginate results from a scan() or query().

        Args:
            func (method): Function to invoke (ALERTS_TABLE.scan or ALERTS_TABLE.query)
            func_kwargs (dict): Keyword arguments to pass to the scan/query function.
                The kwargs will be modified if pagination is necessary.

        Yields:
            dict: Each item (row) from the response
        """
        while True:
            response = func(**func_kwargs)
            for item in response.get('Items', []):
                yield item

            if response.get('LastEvaluatedKey'):
                func_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            else:
                return

    def rule_names(self):
        """Returns the set of distinct rule names (str) found in the table."""
        kwargs = {
            'ProjectionExpression': 'RuleName',
            'Select': 'SPECIFIC_ATTRIBUTES'
        }
        return set(item['RuleName'] for item in self._paginate(self.table.scan, kwargs))

    def pending_alerts(self, rule_name, alert_proc_timeout_sec):
        """Find all alerts for the given rule which need to be dispatched to the alert processor.

        Args:
            rule_name (str): Select all alerts from this rule name
            alert_proc_timeout_sec (int): Alert processor timeout
                This is used to determine whether an alert could still be in progress

        Yields:
            dict: Each alert (row) with all columns and values.
        """
        kwargs = {
            # Include only those alerts which have not yet dispatched or were dispatched more than
            # ALERT_PROCESSOR_TIMEOUT seconds ago
            'FilterExpression': (Attr('Dispatched').not_exists() |
                                 Attr('Dispatched').lt(int(time.time()) - alert_proc_timeout_sec)),
            'KeyConditionExpression': Key('RuleName').eq(rule_name),
            'Select': 'ALL_ATTRIBUTES'
        }
        for item in self._paginate(self.table.query, kwargs):
            yield item

    def mark_as_dispatched(self, rule_name, alert_id):
        """Mark a specific alert as dispatched (in progress)."""
        # Update the alerts table with the dispatch time, but only if the alert still exists.
        # (The alert processor could have deleted the alert before the table update finishes).
        try:
            self.table.update_item(
                Key={'RuleName': rule_name, 'AlertID': alert_id},
                UpdateExpression='SET Dispatched = :now ADD Attempts :one',
                ExpressionAttributeValues={':now': int(time.time()), ':one': 1},
                ConditionExpression='attribute_exists(AlertID)'
            )
        except ClientError as error:
            # The update will fail if the alert was already deleted by the alert processor,
            # in which case there's nothing to do! Any other error is re-raised.
            if error.response['Error']['Code'] != 'ConditionalCheckFailedException':
                raise


class AlertEncoder(json.JSONEncoder):
    """Custom JSON encoder which handles sets and Decimals."""
    def default(self, obj):  # pylint: disable=arguments-differ,method-hidden
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, Decimal):
            return float(obj)
        return json.JSONEncoder.default(self, obj)


# TODO: Alert merging will be implemented here
class AlertMerger(object):
    """Dispatch alerts to the alert processor."""
    ALERT_MERGER = None  # AlertMerger instance which can be re-used across Lambda invocations

    @classmethod
    def get_instance(cls):
        """Get an instance of the AlertMerger, using a cached version if possible."""
        if not cls.ALERT_MERGER:
            cls.ALERT_MERGER = AlertMerger()
        return cls.ALERT_MERGER

    def __init__(self):
        self.alerts_db = AlertTable(os.environ['ALERTS_TABLE'])
        self.alert_proc = os.environ['ALERT_PROCESSOR']
        self.alert_proc_timeout = int(os.environ['ALERT_PROCESSOR_TIMEOUT_SEC'])
        self.lambda_client = boto3.client('lambda')

    def _dispatch_alert(self, alert):
        """Dispatch all alerts which need to be sent to the rule processor."""
        this_attempt_num = alert.get('Attempts', 0) + 1
        LOGGER.info('Dispatching alert %s to %s (attempt %d)',
                    alert['AlertID'], self.alert_proc, this_attempt_num)
        MetricLogger.log_metric(ALERT_MERGER_NAME, MetricLogger.ALERT_ATTEMPTS, this_attempt_num)

        self.lambda_client.invoke(
            FunctionName=self.alert_proc,
            InvocationType='Event',
            Payload=json.dumps(alert, cls=AlertEncoder, separators=(',', ':')),
            Qualifier='production'
        )
        self.alerts_db.mark_as_dispatched(alert['RuleName'], alert['AlertID'])

    def dispatch(self):
        """Find and dispatch all pending alerts to the alert processor."""
        for rule_name in self.alerts_db.rule_names():
            for alert in self.alerts_db.pending_alerts(rule_name, self.alert_proc_timeout):
                self._dispatch_alert(alert)


def handler(event, context):  # pylint: disable=unused-argument
    """Entry point for the alert merger."""
    AlertMerger.get_instance().dispatch()

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
import time

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

from stream_alert.shared.alert import Alert


class AlertTable(object):
    """Provides convenience methods for accessing and modifying the alerts table."""
    def __init__(self, table_name):
        self._table = boto3.resource('dynamodb').Table(table_name)

    @property
    def name(self):
        """Name of the DynamoDB table used to store alerts."""
        return self._table.table_name

    # ---------- Query/Scan Operations ----------

    @staticmethod
    def _paginate(func, func_kwargs):
        """Paginate results from a scan() or query().

        Args:
            func (method): Function to invoke (scan or query).
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
        """Find all of the distinct rule names in the table.

        Returns:
            set: Set of string rule names
        """
        kwargs = {
            'ProjectionExpression': 'RuleName',
            'Select': 'SPECIFIC_ATTRIBUTES'
        }
        return set(item['RuleName'] for item in self._paginate(self._table.scan, kwargs))

    def pending_alerts(self, rule_name, alert_proc_timeout_sec):
        """Find all alerts for the given rule which need to be dispatched to the alert processor.

        Args:
            rule_name (str): Select all alerts from this rule name
            alert_proc_timeout_sec (int): Alert processor timeout
                This is used to determine whether an alert could still be in progress

        Yields:
            Alert: An alert instance for each row in the Dynamo table
        """
        kwargs = {
            # We need a consistent read here in order to pick up the most recent updates from the
            # alert processor. Otherwise, deleted/updated alerts may not yet have propagated.
            'ConsistentRead': True,

            # Include only those alerts which have not yet dispatched or were dispatched more than
            # ALERT_PROCESSOR_TIMEOUT seconds ago
            'FilterExpression': (Attr('Dispatched').lt(int(time.time()) - alert_proc_timeout_sec)),

            'KeyConditionExpression': Key('RuleName').eq(rule_name)
        }
        for item in self._paginate(self._table.query, kwargs):
            yield Alert.create_from_dynamo_record(item)

    def get_alert(self, rule_name, alert_id):
        """Get a single alert from the alerts table.

        Args:
            rule_name (str): Name of the rule the alert triggered on
            alert_id (str): Alert UUID

        Returns:
            Alert: Instance of an alert, or None if the alert was not found.
        """
        kwargs = {
            'ConsistentRead': True,
            'KeyConditionExpression': Key('RuleName').eq(rule_name) & Key('AlertID').eq(alert_id)
        }
        items = list(self._paginate(self._table.query, kwargs))
        return Alert.create_from_dynamo_record(items[0]) if items else None

    # ---------- Add/Delete/Update Operations ----------

    def add_alerts(self, alerts):
        """Add a list of alerts to the table.

        Args:
            alerts (list): List of Alerts to add
        """
        # The batch_writer() automatically re-sends failed items.
        with self._table.batch_writer() as batch:
            for alert in alerts:
                batch.put_item(Item=alert.dynamo_record())

    @staticmethod
    def _is_conditional_failure(error):
        """Returns True if the given ClientError was caused by a failed conditional check."""
        return error.response['Error']['Code'] == 'ConditionalCheckFailedException'

    def mark_as_dispatched(self, alert):
        """Mark a specific alert as dispatched (in progress).

        Args:
            alert (Alert): Alert instance which has just been sent to the alert processor
        """
        # Update the alerts table with the dispatch time, but only if the alert still exists.
        # (The alert processor could have deleted the alert before this table update finishes).
        try:
            self._table.update_item(
                Key=alert.dynamo_key,
                UpdateExpression='SET Attempts = :attempts, Dispatched = :dispatched',
                ExpressionAttributeValues={
                    ':dispatched': alert.dispatched, ':attempts': alert.attempts},
                ConditionExpression='attribute_exists(AlertID)'
            )
        except ClientError as error:
            # The update will fail if the alert was already deleted by the alert processor,
            # in which case there's nothing to do! Any other error is re-raised.
            if not self._is_conditional_failure(error):
                raise

    def update_retry_outputs(self, alert):
        """Update the table with a new set of outputs to be retried.

        Args:
            alert (Alert): Alert instance with the list of failed outputs
        """
        try:
            self._table.update_item(
                Key=alert.dynamo_key,
                UpdateExpression='SET RetryOutputs = :failed_outputs',
                ExpressionAttributeValues={':failed_outputs': alert.retry_outputs},
                ConditionExpression='attribute_exists(AlertID)'
            )
        except ClientError as error:
            # If the alert no longer exists, no need to update it. This could happen if the alert
            # was manually deleted or if multiple alert processors somehow sent the same alert.
            if not self._is_conditional_failure(error):
                raise

    def delete_alert(self, rule_name, alert_id):
        """Remove an alert from the table.

        Args:
            rule_name (str): Name of the rule which triggered the alert
            alert_id (str): Alert UUID
        """
        # Note: we can't pass an Alert instance here because we can also delete invalid alerts
        self._table.delete_item(Key={'RuleName': rule_name, 'AlertID': alert_id})

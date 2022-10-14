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
from datetime import datetime, timedelta

import boto3
from boto3.dynamodb.conditions import Attr, Key

from streamalert.shared.alert import Alert
from streamalert.shared.helpers.dynamodb import ignore_conditional_failure


class AlertTable:
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
            yield from response.get('Items', [])
            if response.get('LastEvaluatedKey'):
                func_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            else:
                return

    def rule_names_generator(self):
        """Returns a generator that yields unique rule_names of items on the table

        Each unique name is yielded only once. Additionally, because the names materialized over
        several paginated calls, it is not 100% guaranteed to return every possible rule_name on
        the Alert Table; if there are other operations that are writing items to the DynamoDB table,
        it is possible for certain names to get skipped.

        Returns:
            Generator[str]
        """
        kwargs = {
            'ProjectionExpression': 'RuleName',
            'Select': 'SPECIFIC_ATTRIBUTES',

            # It is acceptable to use inconsistent reads here to reduce read capacity units
            # consumed, as there is already no guarantee of consistent in the rule names due to
            # pagination.
            'ConsistentRead': False,
        }

        rule_names = set()
        for item in self._paginate(self._table.scan, kwargs):
            name = item['RuleName']
            if name in rule_names:
                continue

            rule_names.add(name)
            yield name

    def get_alert_records(self, rule_name, alert_proc_timeout_sec):
        """Find all alerts for the given rule which need to be dispatched to the alert processor.

        Args:
            rule_name (str): Select all alerts from this rule name
            alert_proc_timeout_sec (int): Alert processor timeout
                This is used to determine whether an alert could still be in progress

        Yields:
            dict: Each row in the Dynamo table which is not being worked on by the alert processor.
        """
        # Any alert which was recently dispatched to the alert processor may still be in progress,
        # so we'll skip over those for now.
        in_progress_threshold = datetime.utcnow() - timedelta(seconds=alert_proc_timeout_sec)

        kwargs = {
            # We need a consistent read here in order to pick up the most recent updates from the
            # alert processor. Otherwise, deleted/updated alerts may not yet have propagated.
            'ConsistentRead':
            True,

            # Include only those alerts which have not yet dispatched or were dispatched more than
            # ALERT_PROCESSOR_TIMEOUT seconds ago.
            'FilterExpression':
            (Attr('Dispatched').lt(in_progress_threshold.strftime(Alert.DATETIME_FORMAT))),
            'KeyConditionExpression':
            Key('RuleName').eq(rule_name)
        }
        yield from self._paginate(self._table.query, kwargs)

    def get_alert_record(self, rule_name, alert_id):
        """Get a single alert record from the alerts table.

        Args:
            rule_name (str): Name of the rule the alert triggered on
            alert_id (str): Alert UUID

        Returns:
            (dict): Dynamo record corresponding to this alert, or None if the alert was not found.
        """
        kwargs = {
            'ConsistentRead': True,
            'KeyConditionExpression': Key('RuleName').eq(rule_name) & Key('AlertID').eq(alert_id)
        }
        items = list(self._paginate(self._table.query, kwargs))
        return items[0] if items else {}

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

    @ignore_conditional_failure
    def mark_as_dispatched(self, alert):
        """Mark a specific alert as dispatched (in progress).

        Args:
            alert (Alert): Alert instance which has just been sent to the alert processor
        """
        # Update the alerts table with the dispatch time, but only if the alert still exists.
        # (The alert processor could have deleted the alert before this table update finishes).
        self._table.update_item(
            Key=alert.dynamo_key,
            UpdateExpression='SET Attempts = :attempts, Dispatched = :dispatched',
            ExpressionAttributeValues={
                ':attempts': alert.attempts,
                ':dispatched': alert.dispatched.strftime(Alert.DATETIME_FORMAT)
            },
            ConditionExpression='attribute_exists(AlertID)')

    @ignore_conditional_failure
    def update_sent_outputs(self, alert):
        """Update the table with the set of outputs which have sent successfully.

        Args:
            alert (Alert): Alert instance with sent outputs already updated.
        """
        self._table.update_item(Key=alert.dynamo_key,
                                UpdateExpression='SET OutputsSent = :outputs_sent',
                                ExpressionAttributeValues={':outputs_sent': alert.outputs_sent},
                                ConditionExpression='attribute_exists(AlertID)')

    def delete_alerts(self, keys):
        """Remove an alert from the table.

        Args:
            keys (list): List of (rule_name, alert_id) str tuples
        """
        with self._table.batch_writer() as batch:
            for rule_name, alert_id in keys:
                batch.delete_item(Key={'RuleName': rule_name, 'AlertID': alert_id})

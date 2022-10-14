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
from datetime import datetime

import boto3

from streamalert.shared.alert import Alert, AlertCreationError
from streamalert.shared.alert_table import AlertTable
from streamalert.shared.logger import get_logger
from streamalert.shared.metrics import ALERT_MERGER_NAME, MetricLogger

LOGGER = get_logger(__name__)


class AlertMergeGroup:
    """A list of alerts within a single merge window which match on their merge keys."""
    # In order to limit the size of a merged alert, cap the maximum number that can be merged.
    MAX_ALERTS_PER_GROUP = 50

    def __init__(self, alert):
        """Initialize the group with the oldest alert remaining."""
        self.alerts = [alert]

    def add(self, alert):
        """Try adding an Alert to this merge group.

        Returns:
            True if the alert matches this group and was added, False otherwise.
        """
        if len(self.alerts) >= self.MAX_ALERTS_PER_GROUP:
            return False

        if alert.can_merge(self.alerts[0]):
            self.alerts.append(alert)
            return True
        return False


class AlertMerger:
    """Dispatch alerts to the alert processor."""
    ALERT_MERGER = None  # AlertMerger instance which can be re-used across Lambda invocations

    # Async invocations of Lambda functions are capped at 128KB.
    # Set the max payload size to slightly under that to account for the rest of the message.
    MAX_LAMBDA_PAYLOAD_SIZE = 126000

    # The maximum number of alerts that are loaded into memory for a single rule, during a single
    # loop in the Alert Merger.
    ALERT_GENERATOR_DEFAULT_LIMIT = 5000

    @classmethod
    def get_instance(cls):
        """Get an instance of the AlertMerger, using a cached version if possible."""
        if not cls.ALERT_MERGER:
            cls.ALERT_MERGER = AlertMerger()
        return cls.ALERT_MERGER

    def __init__(self):
        self.table = AlertTable(os.environ['ALERTS_TABLE'])
        self.alert_proc = os.environ['ALERT_PROCESSOR']
        self.alert_proc_timeout = int(os.environ['ALERT_PROCESSOR_TIMEOUT_SEC'])
        self.lambda_client = boto3.client('lambda')

        # FIXME (derek.wang) Maybe make this configurable in the future
        self._alert_generator_limit = self.ALERT_GENERATOR_DEFAULT_LIMIT

    def _alert_generator(self, rule_name):
        """
        Returns a generator that yields Alert instances triggered from the given rule name.

        To limit memory consumption, the generator yields a maximum number of alerts, defined
        by self._alert_generator_limit.
        """
        generator = self.table.get_alert_records(rule_name, self.alert_proc_timeout)
        for idx, record in enumerate(generator, start=1):
            try:
                yield Alert.create_from_dynamo_record(record)
            except AlertCreationError:
                LOGGER.exception('Invalid alert record %s', record)
                continue

            if idx >= self._alert_generator_limit:
                LOGGER.warning('Alert Merger reached alert limit of %d for rule "%s"',
                               self._alert_generator_limit, rule_name)
                return

    @staticmethod
    def _merge_groups(alerts):
        """Gather alerts into groupings which can be merged together and sent now.

        Args:
            alerts (list): List of Alert instances with defined merge configuration.

        Returns:
            list<AlertMergeGroup>: Each returned merge group has the following properties:
                (1) The oldest alert is older than its merge window (i.e. should be sent now), AND
                (2) All alerts in the merge group fit within a single merge window, AND
                (3) All alerts in the merge group have the same values for all of their merge keys.

            Alerts which are too recent to fit in any merge group are excluded from the results.
        """
        merge_groups = []

        for alert in sorted(alerts):
            # Iterate over alerts (in order of creation) and try to add them to each merge group.
            if not any(group.add(alert) for group in merge_groups):
                # The alert doesn't fit in any merge group - try creating a new one.
                if datetime.utcnow() < alert.created + alert.merge_window:
                    # This alert is too recent - no other alerts can be merged. Stop here.
                    break
                merge_groups.append(AlertMergeGroup(alert))

        return merge_groups

    def _dispatch_alert(self, alert):
        """Dispatch a single alert to the alert processor."""
        alert.attempts += 1
        LOGGER.info('Dispatching %s to %s (attempt %d)', alert, self.alert_proc, alert.attempts)
        MetricLogger.log_metric(ALERT_MERGER_NAME, MetricLogger.ALERT_ATTEMPTS, alert.attempts)

        record_payload = json.dumps(alert.dynamo_record(), default=list, separators=(',', ':'))

        if len(record_payload) <= self.MAX_LAMBDA_PAYLOAD_SIZE:
            # The entire alert fits in the Lambda payload - send it all
            payload = record_payload
        else:
            # The alert is too big - the alert processor will have to pull it from Dynamo
            payload = json.dumps(alert.dynamo_key)

        self.lambda_client.invoke(FunctionName=self.alert_proc,
                                  InvocationType='Event',
                                  Payload=payload,
                                  Qualifier='production')

        alert.dispatched = datetime.utcnow()
        self.table.mark_as_dispatched(alert)

    def dispatch(self):
        """Find and dispatch all pending alerts to the alert processor."""
        # To reduce the API calls to Dynamo, batch all additions and deletions until the end.
        merged_alerts = []  # List of newly created merge alerts
        alerts_to_delete = []  # List of alerts which can be deleted

        for rule_name in self.table.rule_names_generator():
            merge_enabled_alerts = []
            for alert in self._alert_generator(rule_name):
                if alert.remaining_outputs:
                    # If an alert still has pending outputs, it needs to be sent immediately.
                    # For example, all alerts are sent to the default firehose now even if they will
                    # later be merged when sending to other outputs.
                    self._dispatch_alert(alert)
                elif alert.merge_enabled:
                    # This alert has finished sending to non-merged outputs; it is now a candidate
                    # for alert merging.
                    merge_enabled_alerts.append(alert)
                else:
                    # This alert has sent successfully but doesn't need to be merged.
                    # It should have been deleted by the alert processor, but we can do it now.
                    alerts_to_delete.append(alert)

            for group in self._merge_groups(merge_enabled_alerts):
                # Create a new merged Alert.
                new_alert = Alert.merge(group.alerts)
                LOGGER.info('Merged %d alerts into a new alert with ID %s', len(group.alerts),
                            new_alert.alert_id)
                merged_alerts.append(new_alert)

                # Since we already guaranteed that the original alerts have sent to the unmerged
                # outputs (e.g. default firehose), they can be safely marked for deletion.
                alerts_to_delete.extend(group.alerts)

        if merged_alerts:
            # Add new merged alerts to the alerts table and send them to the alert processor.
            self.table.add_alerts(merged_alerts)
            for alert in merged_alerts:
                self._dispatch_alert(alert)

        if alerts_to_delete:
            self.table.delete_alerts([(alert.rule_name, alert.alert_id)
                                      for alert in alerts_to_delete])


def handler(event, context):  # pylint: disable=unused-argument
    """Entry point for the alert merger."""
    AlertMerger.get_instance().dispatch()

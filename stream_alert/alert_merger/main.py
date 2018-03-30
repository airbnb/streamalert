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
import json
import os
import time

from stream_alert.alert_merger import LOGGER
from stream_alert.shared.alert_table import AlertTable
from stream_alert.shared.metrics import ALERT_MERGER_NAME, MetricLogger

import boto3


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
        self.table = AlertTable(os.environ['ALERTS_TABLE'])
        self.alert_proc = os.environ['ALERT_PROCESSOR']
        self.alert_proc_timeout = int(os.environ['ALERT_PROCESSOR_TIMEOUT_SEC'])
        self.lambda_client = boto3.client('lambda')

    def _dispatch_alert(self, alert):
        """Dispatch all alerts which need to be sent to the rule processor."""
        alert.attempts += 1
        LOGGER.info('Dispatching %s to %s (attempt %d)', alert, self.alert_proc, alert.attempts)
        MetricLogger.log_metric(ALERT_MERGER_NAME, MetricLogger.ALERT_ATTEMPTS, alert.attempts)

        self.lambda_client.invoke(
            FunctionName=self.alert_proc,
            InvocationType='Event',
            # The maximum async invocation size for Lambda is 128 KB. Since alerts could be larger
            # than that, the alert processor is responsible for pulling the full record.
            Payload=json.dumps(alert.dynamo_key),
            Qualifier='production'
        )

        alert.last_dispatched = int(time.time())
        self.table.mark_as_dispatched(alert)

    def dispatch(self):
        """Find and dispatch all pending alerts to the alert processor."""
        for rule_name in self.table.rule_names():
            for alert in self.table.pending_alerts(rule_name, self.alert_proc_timeout):
                self._dispatch_alert(alert)


def handler(event, context):  # pylint: disable=unused-argument
    """Entry point for the alert merger."""
    AlertMerger.get_instance().dispatch()

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
import os

from botocore.exceptions import ClientError

from stream_alert.rule_processor import FUNCTION_NAME
from stream_alert.shared.alert_table import AlertTable
from stream_alert.shared.logger import get_logger
from stream_alert.shared.metrics import MetricLogger


LOGGER = get_logger(__name__)


class AlertForwarder(object):
    """Sends alerts to the Alert Processor and the alerts Dynamo table."""

    def __init__(self):
        """Initialize the Forwarder with the boto3 clients and resource names."""
        self._table = AlertTable(os.environ['ALERTS_TABLE'])

    def send_alerts(self, alerts):
        """Send alerts to the Dynamo table.

        Args:
            alerts (list): A list of Alert instances to save to Dynamo.
        """
        try:
            self._table.add_alerts(alerts)
            LOGGER.info('Successfully sent %d alert(s) to dynamo:%s', len(alerts), self._table.name)
        except ClientError:
            # add_alerts() automatically retries transient errors - any raised ClientError
            # is likely unrecoverable. Log an exception and metric
            LOGGER.exception('Error saving alerts to Dynamo')
            MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.FAILED_DYNAMO_WRITES, 1)

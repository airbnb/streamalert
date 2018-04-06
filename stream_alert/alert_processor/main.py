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
from __future__ import absolute_import  # Suppresses RuntimeWarning import error in Lambda
import json
import os

from stream_alert.alert_processor import LOGGER
from stream_alert.alert_processor.outputs.output_base import StreamAlertOutput
from stream_alert.shared import backoff_handlers, NORMALIZATION_KEY, resources
from stream_alert.shared.alert_table import AlertTable

import backoff
from botocore.exceptions import ClientError


class AlertProcessor(object):
    """Orchestrates delivery of alerts to the appropriate dispatchers."""
    ALERT_PROCESSOR = None  # AlertProcessor instance which can be re-used across Lambda invocations
    BACKOFF_MAX_TRIES = 5
    OUTPUT_CONFIG_PATH = 'conf/outputs.json'

    @classmethod
    def get_instance(cls, invoked_function_arn):
        """Get an instance of the AlertProcessor, using a cached version if possible."""
        if not cls.ALERT_PROCESSOR:
            cls.ALERT_PROCESSOR = AlertProcessor(invoked_function_arn)
        return cls.ALERT_PROCESSOR

    def __init__(self, invoked_function_arn):
        """Initialization logic that can be cached across invocations.

        Args:
            invoked_function_arn (str): The ARN of the alert processor when it was invoked.
                This is used to calculate region, account, and prefix.
        """
        # arn:aws:lambda:REGION:ACCOUNT:function:PREFIX_streamalert_alert_processor:production
        split_arn = invoked_function_arn.split(':')
        self.region = split_arn[3]
        self.account_id = split_arn[4]
        self.prefix = split_arn[6].split('_')[0]

        # Merge user-specified output configuration with the required output configuration
        with open(self.OUTPUT_CONFIG_PATH) as f:
            output_config = json.load(f)
        self.config = resources.merge_required_outputs(output_config, self.prefix)

        self.alerts_table = AlertTable(os.environ['ALERTS_TABLE'])

    def _create_dispatcher(self, output):
        """Create a dispatcher for the given output.

        Args:
            output (str): Alert output, e.g. "aws-sns:topic-name"

        Returns:
            OutputDispatcher: Based on the output type.
                Returns None if the output is invalid or not defined in the config.
        """
        try:
            service, descriptor = output.split(':')
        except ValueError:
            LOGGER.error('Improperly formatted output [%s]. Outputs for rules must '
                         'be declared with both a service and a descriptor for the '
                         'integration (ie: \'slack:my_channel\')', output)
            return None

        if service not in self.config or descriptor not in self.config[service]:
            LOGGER.error('The output \'%s\' does not exist!', output)
            return None

        return StreamAlertOutput.create_dispatcher(
            service, self.region, self.account_id, self.prefix, self.config)

    @staticmethod
    def _send_alert(alert, output, dispatcher):
        """Send a single alert to the given output.

        Args:
            alert (Alert): Alert to be sent
            output (str):

        Returns:
            bool: True if the alert was sent successfully.
        """
        LOGGER.info('Sending %s to %s', alert, output)
        try:
            return dispatcher.dispatch(alert, output.split(':')[1])
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception('Exception when sending %s to %s. Alert:\n%s',
                             alert, output, repr(alert))
            return False

    def _send_alerts(self, alert):
        """Send an alert to each output.

        Args:
            alert (Alert): Alert to send

        Returns:
            dict: Maps output (str) to whether it sent successfully (bool)
                Invalid outputs are excluded
        """
        result = {}

        for output in alert.remaining_outputs:
            dispatcher = self._create_dispatcher(output)
            if not dispatcher:
                continue  # Skip invalid output

            result[output] = self._send_alert(alert, output, dispatcher)

        alert.retry_outputs = set(output for output, success in result.items() if not success)
        return result

    @backoff.on_exception(backoff.expo, ClientError,
                          max_tries=BACKOFF_MAX_TRIES, jitter=backoff.full_jitter,
                          on_backoff=backoff_handlers.backoff_handler,
                          on_success=backoff_handlers.success_handler,
                          on_giveup=backoff_handlers.giveup_handler)
    def _update_table(self, alert, output_results):
        """Update the alerts table based on the results of the outputs.

        Args:
            alert (Alert): Alert instance which was sent
            output_results (dict): Maps output (str) to whether it sent successfully (bool)
        """
        if not output_results:
            return

        if all(output_results.values()):
            # All outputs sent successfully - delete Dynamo entry
            self.alerts_table.delete_alert(alert.rule_name, alert.alert_id)
        elif any(output_results.values()):
            # At least one output succeeded - update the table with those outputs which need retried
            self.alerts_table.update_retry_outputs(alert)
        # else: If all outputs failed, no table updates are necessary

    def run(self, rule_name, alert_id):
        """Run the alert processor!

        Args:
            rule_name (str): Name of the rule which triggered the alert
            alert_id (str): Alert UUID

        Returns:
            dict: Maps output (str) to whether it sent successfully (bool)
                Invalid outputs are excluded
        """
        alert = self.alerts_table.get_alert(rule_name, alert_id)
        if not alert:
            LOGGER.error('Alert %s does not exist', alert_id)
            return

        # Remove normalization key from the record
        # TODO: Consider including this in at least some outputs, e.g. default Athena firehose
        if NORMALIZATION_KEY in alert.record:
            del alert.record[NORMALIZATION_KEY]

        result = self._send_alerts(alert)
        self._update_table(alert, result)
        return result


def handler(event, context):
    """StreamAlert Alert Processor - entry point

    Args:
        event (dict): Key to lookup in the alerts table: {
            'AlertID': str,  # UUID
            'RuleName': str  # Non-empty rule name
        }
        context (AWSLambdaContext): Lambda invocation context

    Returns:
        dict: Maps output (str) to whether it sent successfully (bool)
            This includes only valid outputs which the alert processor attempted to send.
    """
    event_name = event['RuleName']
    alert_id = event['AlertID']
    return AlertProcessor.get_instance(context.invoked_function_arn).run(event_name, alert_id)

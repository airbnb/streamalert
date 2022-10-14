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
from os import environ as env

import backoff
from botocore.exceptions import ClientError

from streamalert.alert_processor.outputs.output_base import StreamAlertOutput
from streamalert.shared import backoff_handlers, resources
from streamalert.shared.alert import Alert, AlertCreationError
from streamalert.shared.alert_table import AlertTable
from streamalert.shared.config import load_config
from streamalert.shared.logger import get_logger
from streamalert.shared.normalize import Normalizer

LOGGER = get_logger(__name__)


class AlertProcessor:
    """Orchestrates delivery of alerts to the appropriate dispatchers."""
    ALERT_PROCESSOR = None  # AlertProcessor instance which can be re-used across Lambda invocations
    BACKOFF_MAX_TRIES = 5

    @classmethod
    def get_instance(cls):
        """Get an instance of the AlertProcessor, using a cached version if possible."""
        if not cls.ALERT_PROCESSOR:
            cls.ALERT_PROCESSOR = AlertProcessor()
        return cls.ALERT_PROCESSOR

    def __init__(self):
        """Initialization logic that can be cached across invocations"""
        # Merge user-specified output configuration with the required output configuration
        output_config = load_config(include={'outputs.json'})['outputs']
        self.config = resources.merge_required_outputs(output_config, env['STREAMALERT_PREFIX'])

        self.alerts_table = AlertTable(env['ALERTS_TABLE'])

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
            LOGGER.error(
                'Improperly formatted output [%s]. Outputs for rules must '
                'be declared with both a service and a descriptor for the '
                'integration (ie: \'slack:my_channel\')', output)
            return None

        if service not in self.config or descriptor not in self.config[service]:
            LOGGER.error('The output \'%s\' does not exist!', output)
            return None

        return StreamAlertOutput.create_dispatcher(service, self.config)

    def _send_to_outputs(self, alert):
        """Send an alert to each remaining output.

        Args:
            alert (Alert): Alert to send

        Returns:
            dict: Maps output (str) to whether it sent successfully (bool)
        """
        result = {}

        for output in alert.remaining_outputs:
            dispatcher = self._create_dispatcher(output)
            result[output] = dispatcher.dispatch(alert, output) if dispatcher else False

        alert.outputs_sent = {output for output, success in list(result.items()) if success}

        return result

    @backoff.on_exception(backoff.expo,
                          ClientError,
                          max_tries=BACKOFF_MAX_TRIES,
                          jitter=backoff.full_jitter,
                          on_backoff=backoff_handlers.backoff_handler(),
                          on_success=backoff_handlers.success_handler(),
                          on_giveup=backoff_handlers.giveup_handler())
    def _update_table(self, alert, output_results):
        """Update the alerts table based on the results of the outputs.

        Args:
            alert (Alert): Alert instance which was sent
            output_results (dict): Maps output (str) to whether it sent successfully (bool)
        """
        if not output_results:
            return

        if all(output_results.values()) and not alert.merge_enabled:
            # All outputs sent successfully and the alert will not be merged later - delete it now
            self.alerts_table.delete_alerts([(alert.rule_name, alert.alert_id)])
        elif any(output_results.values()):
            # At least one output succeeded - update table accordingly
            self.alerts_table.update_sent_outputs(alert)
        # else: If all outputs failed, no table updates are necessary

    def run(self, event):
        """Run the alert processor!

        Args:
            event (dict): Lambda invocation event containing at least the rule name and alert ID.

        Returns:
            dict: Maps output (str) to whether it sent successfully (bool).
                An empty dict is returned if the Alert was improperly formatted.
        """
        # Grab the alert record from Dynamo (if needed).
        if set(event) == {'AlertID', 'RuleName'}:
            LOGGER.info('Retrieving %s from alerts table', event)
            alert_record = self.alerts_table.get_alert_record(event['RuleName'], event['AlertID'])
            if not alert_record:
                LOGGER.error('%s does not exist in the alerts table', event)
                return {}
        else:
            alert_record = event

        # Convert record to an Alert instance.
        try:
            alert = Alert.create_from_dynamo_record(alert_record)
        except AlertCreationError:
            LOGGER.exception('Invalid alert %s', event)
            return {}

        # Remove normalization key from the record.
        # TODO: Consider including this in at least some outputs, e.g. default Athena firehose
        if Normalizer.NORMALIZATION_KEY in alert.record:
            del alert.record[Normalizer.NORMALIZATION_KEY]

        result = self._send_to_outputs(alert)
        self._update_table(alert, result)
        return result


def handler(event, _):
    """StreamAlert Alert Processor - entry point

    Args:
        event (dict): Contains either the entire Dynamo record or just the rule name and alert ID {
            'AlertID': str,  # UUID
            'RuleName': str,  # Non-empty rule name

            # Other data present only if the full record was sent
            'Record': ...,
            ...
        }
        context (AWSLambdaContext): Lambda invocation context

    Returns:
        dict: Maps output (str) to whether it sent successfully (bool).
            An empty dict is returned if the alert was improperly formatted.
    """
    return AlertProcessor.get_instance().run(event)

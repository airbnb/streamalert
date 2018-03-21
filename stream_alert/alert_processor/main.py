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
from stream_alert.alert_processor.helpers import ordered_dict
from stream_alert.alert_processor.outputs.output_base import StreamAlertOutput
from stream_alert.shared import backoff_handlers, NORMALIZATION_KEY, resources

import backoff
import boto3
from botocore.exceptions import ClientError

ALERT_PROCESSOR = None  # Cached instantiation of an Alert Processor


class AlertProcessor(object):
    """Orchestrates delivery of alerts to the appropriate dispatchers."""
    ALERT_PROCESSOR = None  # AlertProcessor instance which can be re-used across Lambda invocations
    BACKOFF_MAX_TRIES = 6
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

        self.alerts_table = boto3.resource('dynamodb').Table(os.environ['ALERTS_TABLE'])

    @staticmethod
    def _build_alert_payload(record):
        """Transform a raw Dynamo record into a payload ready for dispatching.

        Args:
            record (dict): A row in the Dynamo alerts table

        Returns:
            OrderedDict: An alert payload ready to be sent to output dispatchers.
        """
        # Any problems with the alert keys or JSON loading will raise an exception here.
        # This is what we want - an invalid alert is a show-stopper and shouldn't ever happen.
        return ordered_dict({
            'cluster': record['Cluster'],
            'created': record['Created'],
            'id': record['AlertID'],
            'log_source': record['LogSource'],
            'log_type': record['LogType'],
            'outputs': record['Outputs'],
            'record': json.loads(record['Record']),
            'rule_description': record['RuleDescription'],
            'rule_name': record['RuleName'],
            'source_entity': record['SourceEntity'],
            'source_service': record['SourceService']
        }, exclude_keys={NORMALIZATION_KEY})

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
    def _send_alert(alert_payload, output, dispatcher):
        """Send a single alert to the given output.

        Returns:
            bool: True if the alert was sent successfully.
        """
        LOGGER.info('Sending alert %s to %s', alert_payload['id'], output)
        try:
            return dispatcher.dispatch(descriptor=output.split(':')[1],
                                       rule_name=alert_payload['rule_name'],
                                       alert=alert_payload)
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception('Exception when sending alert %s to %s. Alert:\n%s',
                             alert_payload['id'], output, json.dumps(alert_payload, indent=2))
            return False

    @backoff.on_exception(backoff.expo, ClientError,
                          max_tries=BACKOFF_MAX_TRIES, jitter=backoff.full_jitter,
                          on_backoff=backoff_handlers.backoff_handler,
                          on_success=backoff_handlers.success_handler,
                          on_giveup=backoff_handlers.giveup_handler)
    def _update_alerts_table(self, rule_name, alert_id, results):
        """Update the alerts table based on which outputs sent successfully."""
        key = {'RuleName': rule_name, 'AlertID': alert_id}
        if all(results.values()):
            # All outputs sent successfully - delete Dynamo entry
            self.alerts_table.delete_item(Key=key)
        else:
            # List failed outputs as needing a retry
            self.alerts_table.update_item(
                Key=key,
                UpdateExpression='SET RetryOutputs = :failed_outputs',
                ExpressionAttributeValues={
                    ':failed_outputs': set(
                        output for output, success in results.items() if not success)
                }
            )

    def run(self, event):
        """Run the alert processor!

        Args:
            event (dict): Invocation event (record from Dynamo table)

        Returns:
            dict(str, bool): Maps each output to whether it was sent successfully.
                Invalid outputs are excluded from the result.
        """
        payload = self._build_alert_payload(event)

        # Try sending to each output, keeping track of which was successful
        results = {}
        for output in event.get('RetryOutputs') or event['Outputs']:
            dispatcher = self._create_dispatcher(output)
            if dispatcher:
                results[output] = self._send_alert(payload, output, dispatcher)

        self._update_alerts_table(event['RuleName'], event['AlertID'], results)
        return results


def handler(event, context):
    """StreamAlert Alert Processor - entry point

    Args:
        event (dict): Record from the alerts Dynamo table: {
            'AlertID': str,           # UUID
            'Attempts': int,          # Number of attempts to send this alert so far
            'Cluster': str,           # Cluster which generated the alert
            'Created': str,           # Human-readable timestamp when the alert was created
            'Dispatched': int,        # Time (seconds UTC) when the alert was last dispatched
            'LogSource': str,         # Log source (e.g. "binaryalert") which generated the alert
            'LogType' str,            # "json"
            'Outputs': list[str],     # Unique list of service:descriptor output targets
            'Record': str,            # JSON-encoded record body
            'RetryOutputs': list[str] # Optional list of outputs which need to be retried
            'RuleDescription': str    # Non-empty rule description
            'RuleName': str,          # Non-empty rule name
            'SourceEntity': str,      # Name of the alert source (e.g. "my-topic", "sample-channel")
            'SourceService': str,     # Service which generated the alert (e.g. "sns", "slack")
        }
        context (AWSLambdaContext): Lambda invocation context

    Returns:
        dict(str, bool): Maps each output to whether it was sent successfully.
            For example, {'aws-firehose:sample': False, 'slack:example-channel': True}.
            NOTE: Invalid outputs are excluded from the result (they should not be retried)
    """
    return AlertProcessor.get_instance(context.invoked_function_arn).run(event)

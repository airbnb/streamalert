'''
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
'''

import json
import logging

from collections import OrderedDict

from stream_alert.alert_processor.outputs import get_output_dispatcher

logging.basicConfig()
LOGGER = logging.getLogger('StreamOutput')
LOGGER.setLevel(logging.INFO)

def handler(event, context):
    """StreamAlert Alert Processor

    Args:
        event [dict]: contains a 'Records' top level key that holds
            all of the records for this event. Each record dict then
            contains a 'Message' key pointing to the alert payload that
            has been sent from the main StreamAlert Rule processor function
        context [AWSLambdaContext]: basically a namedtuple of properties from AWS
    """
    for record in event.get('Records', []):
        sns_payload = record.get('Sns')
        if not sns_payload:
            continue

        message = sns_payload['Message']
        try:
            alert = json.loads(message)
        except ValueError as err:
            logging.error('an error occurred while decoding message to JSON: %s', err)
            return

        if not 'default' in alert:
            logging.info('malformed alert: %s', alert)
            return

        StreamOutput().run(alert, context)


class StreamOutput(object):
    """Route StreamAlert alerts to their declared outputs.

    Public Methods:
        run
        emit_cloudwatch_metrics
    """
    def run(self, message, context):
        """Send an Alert to its described outputs.

        Args:
            alerts [dict]: SNS message dictionary with the following structure:

            {
                'default': alert
            }

            The alert is another dict with the following structure:

            {
                'rule_name': rule.rule_name,
                'record': record,
                'metadata': {
                    'log': str(payload.log_source),
                    'outputs': rule.outputs,
                    'type': payload.type,
                    'source': {
                        'service': payload.service,
                        'entity': payload.entity
                    }
                }
            }
        """
        alert = message['default']
        rule_name = alert['rule_name']

        # strip out unnecessary keys and sort
        alert = self._sort_dict(alert)

        outputs = alert['metadata']['outputs']
        # Get the output configuration for this rule and send the alert to each
        for output in set(outputs):
            output_info = output.split(':')
            service, descriptor = output_info[0], output_info[1] if len(output_info) > 1 else ""
            region = context.invoked_function_arn.split(':')[3]
            function = context.invoked_function_arn.split(':')[-1]

            # Retrieve the proper class to handle dispatching the alerts of this services
            output_dispatcher = get_output_dispatcher(service, region, function)

            if not output_dispatcher:
                continue

            try:
                output_dispatcher.dispatch(descriptor, rule_name, alert)
            except BaseException as err:
                LOGGER.error('an error occurred while sending alert to %s: %s',
                             service, err)

    @staticmethod
    def emit_cloudwatch_metrics():
        """Send Number of Alerts metric as a CloudWatch metric."""
        raise NotImplementedError

    def _sort_dict(self, unordered_dict):
        """Recursively sort a dictionary

        Args:
            unordered_dict [dict]: an alert dictionary

        Returns:
            [OrderedDict] a sorted version of the dictionary
        """
        result = OrderedDict()
        for key, value in sorted(unordered_dict.items(), key=lambda t: t[0]):
            if isinstance(value, dict):
                result[key] = self._sort_dict(value)
                continue

            result[key] = value

        return result

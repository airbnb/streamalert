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
LOGGER.setLevel(logging.DEBUG)

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

        sns_message = sns_payload['Message']
        try:
            loaded_sns_message = json.loads(sns_message)
        except ValueError as err:
            LOGGER.error('an error occurred while decoding message to JSON: %s', err)
            return

        if not 'default' in loaded_sns_message:
            LOGGER.error('Malformed SNS: %s', loaded_sns_message)
            return

        run(loaded_sns_message, context)

def run(loaded_sns_message, context):
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
    LOGGER.debug(loaded_sns_message)
    alert = loaded_sns_message['default']
    rule_name = alert['rule_name']

    # strip out unnecessary keys and sort
    alert = sort_dict(alert)

    config = load_output_config()

    outputs = alert['metadata']['outputs']
    # Get the output configuration for this rule and send the alert to each
    for output in set(outputs):
        try:
            service, descriptor = output.split(':')
        except ValueError:
            LOGGER.error('outputs for rules must be declared with both a service and a '
                         'descriptor for the integration (ie: \'slack:my_channel\')')

        if not service in config or not descriptor in config[service]:
            LOGGER.error('The output %s does not exist!', output)
            continue

        region = context.invoked_function_arn.split(':')[3]
        function_name = context.function_name

        # Retrieve the proper class to handle dispatching the alerts of this services
        output_dispatcher = get_output_dispatcher(service, region, function_name, config)

        if not output_dispatcher:
            continue

        # try:
        LOGGER.debug('Sending alert to %s', output_dispatcher.__service__)
        output_dispatcher.dispatch(
            descriptor=descriptor,
            rule_name=rule_name,
            alert=alert
            )
        # except BaseException as err:
        #     LOGGER.error('an error occurred while sending alert to %s: %s',
        #                  service, err)

def sort_dict(unordered_dict):
    """Recursively sort a dictionary

    Args:
        unordered_dict [dict]: an alert dictionary

    Returns:
        [OrderedDict] a sorted version of the dictionary
    """
    result = OrderedDict()
    for key, value in sorted(unordered_dict.items(), key=lambda t: t[0]):
        if isinstance(value, dict):
            result[key] = sort_dict(value)
            continue

        result[key] = value

    return result

def load_output_config():
    """Load the outputs configuration file from disk

    Returns:
        [dict] The output configuration settings
    """
    with open('conf/outputs.json') as outputs:
        try:
            config = json.load(outputs)
        except ValueError:
            LOGGER.exception('the outputs.json file could not be loaded into json')

    return config

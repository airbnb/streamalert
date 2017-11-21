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
from collections import OrderedDict
import json

from stream_alert.alert_processor import LOGGER
from stream_alert.alert_processor.helpers import validate_alert
from stream_alert.alert_processor.outputs.output_base import StreamAlertOutput
from stream_alert.shared import NORMALIZATION_KEY


def handler(event, context):
    """StreamAlert Alert Processor

    Args:
        event (dict): contains a 'Records' top level key that holds
            all of the records for this event. Each record dict then
            contains a 'Message' key pointing to the alert payload that
            has been sent from the main StreamAlert Rule processor function
        context (AWSLambdaContext): basically a namedtuple of properties from AWS

    Returns:
        list: Status values. Each entry in the list is a tuple
            consisting of two values. The first value is a boolean that
            indicates if sending was successful and the second value is the
            output configuration info (ie - 'slack:sample_channel')
    """
    # A failure to load the config will log the error in load_output_config
    # and return here
    config = _load_output_config()
    if not config:
        return

    region = context.invoked_function_arn.split(':')[3]
    function_name = context.function_name

    # Return the current list of statuses back to the caller
    return list(run(event, region, function_name, config))


def run(alert, region, function_name, config):
    """Send an Alert to its described outputs.

    Args:
        alert (dict): dictionary representating an alert with the
            following structure:

            {
                'record': record,
                'rule_name': rule.rule_name,
                'rule_description': rule.rule_function.__doc__,
                'log_source': str(payload.log_source),
                'log_type': payload.type,
                'outputs': rule.outputs,
                'source_service': payload.service,
                'source_entity': payload.entity
            }

        region (str): The AWS region of the currently executing Lambda function
        function_name (str): The name of the lambda function
        config (dict): The loaded configuration for outputs from conf/outputs.json

    Yields:
        (bool, str): Dispatch status and name of the output to the handler
    """
    if not validate_alert(alert):
        LOGGER.error('Invalid alert format:\n%s', json.dumps(alert, indent=2))
        return

    LOGGER.debug('Sending alert to outputs:\n%s', json.dumps(alert, indent=2))

    # strip out unnecessary keys and sort
    alert = _sort_dict(alert)

    outputs = alert['outputs']
    # Get the output configuration for this rule and send the alert to each
    for output in set(outputs):
        try:
            service, descriptor = output.split(':')
        except ValueError:
            LOGGER.error('Improperly formatted output [%s]. Outputs for rules must '
                         'be declared with both a service and a descriptor for the '
                         'integration (ie: \'slack:my_channel\')', output)
            continue

        if service not in config or descriptor not in config[service]:
            LOGGER.error('The output \'%s\' does not exist!', output)
            continue

        # Retrieve the proper class to handle dispatching the alerts of this services
        dispatcher = StreamAlertOutput.create_dispatcher(service, region, function_name, config)

        if not dispatcher:
            continue

        LOGGER.debug('Sending alert to %s:%s', service, descriptor)

        sent = False
        try:
            sent = dispatcher.dispatch(descriptor=descriptor,
                                       rule_name=alert['rule_name'],
                                       alert=alert)

        except Exception as err:  # pylint: disable=broad-except
            LOGGER.exception('An error occurred while sending alert '
                             'to %s:%s: %s. alert:\n%s', service, descriptor,
                             err, json.dumps(alert, indent=2))

        # Yield back the result to the handler
        yield sent, output


def _sort_dict(unordered_dict):
    """Recursively sort a dictionary

    Args:
        unordered_dict (dict): an alert dictionary

    Returns:
        OrderedDict: a sorted version of the dictionary
    """
    result = OrderedDict()
    for key, value in sorted(unordered_dict.items(), key=lambda t: t[0]):
        if key == NORMALIZATION_KEY:
            continue
        if isinstance(value, dict):
            result[key] = _sort_dict(value)
            continue

        result[key] = value

    return result


def _load_output_config(config_path='conf/outputs.json'):
    """Load the outputs configuration file from disk

    Returns:
        dict: the output configuration settings
    """
    with open(config_path) as outputs:
        try:
            config = json.load(outputs)
        except ValueError:
            LOGGER.error('The \'%s\' file could not be loaded into json', config_path)
            return

    return config

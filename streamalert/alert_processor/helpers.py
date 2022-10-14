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
from streamalert.shared.publisher import (AlertPublisherRepository,
                                          PublisherAssemblyError)


def elide_string_middle(text, max_length):
    """Replace the middle of the text with ellipses to shorten text to the desired length.

    Args:
        text (str): Text to shorten.
        max_length (int): Maximum allowable length of the string.

    Returns:
        (str) The elided text, e.g. "Some really long tex ... the end."
    """
    if len(text) <= max_length:
        return text

    half_len = (max_length - 5) // 2  # Length of text on either side.
    return f'{text[:half_len]} ... {text[-half_len:]}'


def compose_alert(alert, output, descriptor):
    """Presents the alert as a dict for output classes to send to their API integrations.

    Args:
        alert (Alert): The alert to be dispatched
        output (OutputDispatcher|None): Instance of the output class dispatching this alert
        descriptor (str): The descriptor for the output

    Returns:
        dict
    """

    # FIXME (derek.wang)
    #   this is here because currently the OutputDispatcher sits in a __init__.py module that
    #   performs eager loading of the other output classes. If you load this helper before
    #   the output classes are loaded, it creates a cyclical dependency
    #   helper.py -> output_base.py -> __init__ -> komand.py -> helper.py
    #   This is a temporary workaround
    #   A more permanent solution will involve refactoring the OutputDispatcher to load on-demand
    #   instead of eagerly.
    # pylint: disable=import-outside-toplevel
    from streamalert.alert_processor.outputs.output_base import OutputDispatcher
    # pylint: enable=import-outside-toplevel
    output_service_name = output.__service__ if isinstance(output, OutputDispatcher) else None

    if not output_service_name:
        raise PublisherAssemblyError('Invalid output service')

    publisher = _assemble_alert_publisher_for_output(alert, output_service_name, descriptor)
    return publisher.publish(alert, {})


def _assemble_alert_publisher_for_output(alert, output_service_name, descriptor):
    """Gathers all requested publishers on the alert and returns them as a single Publisher

    Note: The alert.publishers field cannot contain references to actual publisher functions
    or classes, because this field is pulled from Dynamo. It is always going to be a JSON-formatted
    object.

    Args:
        alert (Alert): The alert that is pulled from DynamoDB
        output_service_name (str): The __service__ name of the OutputDispatcher
        descriptor (str): The descriptor of the Output

    Returns:
        AlertPublisher
    """

    alert_publishers = alert.publishers
    publisher_names = []
    if isinstance(alert_publishers, str):
        # Case 1: The publisher is a single string.
        #   apply this single publisher to all outputs + descriptors
        publisher_names.append(alert_publishers)
    elif isinstance(alert_publishers, list):
        # Case 2: The publisher is an array of strings.
        #   apply all publishers to all outputs + descriptors
        publisher_names += alert_publishers
    elif isinstance(alert_publishers, dict):
        # Case 3: The publisher is a dict mapping output strings -> strings or list of strings
        #   apply only publishers under the correct output key. We look under 2 keys:
        #   one key that applies publishers to all outputs for a specific output type, and
        #   another key that applies publishers only to outputs of the type AND matching
        #   descriptor.

        # Order is important here; we load the output-generic publishers first
        if output_service_name and output_service_name in alert_publishers:
            publisher_name_or_names = alert_publishers[output_service_name]
            if isinstance(publisher_name_or_names, list):
                publisher_names = publisher_names + publisher_name_or_names
            else:
                publisher_names.append(publisher_name_or_names)

        # Then load output+descriptor-specific publishers second
        described_output_name = f'{output_service_name}:{descriptor}'
        if described_output_name in alert_publishers:
            publisher_name_or_names = alert_publishers[described_output_name]
            if isinstance(publisher_name_or_names, list):
                publisher_names += publisher_name_or_names
            else:
                publisher_names.append(publisher_name_or_names)

    return AlertPublisherRepository.create_composite_publisher(publisher_names)

"""Initialize logging for the alert processor."""
import importlib
import os

from publishers.core import AlertPublisherRepository


def import_publishers():
    for output_file in os.listdir(os.path.dirname(__file__)):
        # Skip the common base file and any non-py files
        if output_file.startswith(('__init__', 'core')) or not output_file.endswith('.py'):
            continue

        full_import = '.'.join([
            'publishers',
            os.path.splitext(output_file)[0]
        ])

        importlib.import_module(full_import)


import_publishers()


def publish_alert(alert, output, descriptor):
    """Presents the alert as a dict for output classes to send to their API integrations.

    Args:
        alert (Alert): The alert to be dispatched
        output (OutputDispatcher): Instance of the output class dispatching this alert
        descriptor (str): The descriptor for the output

    Returns:
        dict
    """
    publisher = AlertPublisherRepository.assemble_alert_publisher_for_output(
        alert,
        output,
        descriptor
    )
    return publisher.publish(alert, {})

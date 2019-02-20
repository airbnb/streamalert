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

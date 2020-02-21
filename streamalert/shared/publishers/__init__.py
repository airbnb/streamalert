import importlib
import os

from streamalert.shared.publishers.publisher import *

DEFAULT_DIR = os.path.join(os.path.dirname(__file__), 'default_publishers')


# # Import all files containing publishers
for root, _, files in os.walk(DEFAULT_DIR):
    for item in files:
        # Skip any non-py files
        if item.startswith('__init__') or not item.endswith('.py'):
            continue

        basename = os.path.splitext(item)[0]

        full_path = os.path.join(root, basename)
        full_path = full_path.replace(DEFAULT_DIR, '')

        full_import = [
            'streamalert',
            'shared',
            'publishers',
            'default_publishers',
            *full_path.split(os.path.sep)[1:]
        ]

        importlib.import_module('.'.join(full_import))

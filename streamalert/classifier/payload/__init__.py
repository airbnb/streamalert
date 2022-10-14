"""Imports from submodules to make higher up imports easier"""
import importlib
import os

# Import all files containing subclasses of StreamPayload, skipping the common base class
for input_file in os.listdir(os.path.dirname(__file__)):
    # Skip the common base file and any non-py files
    if input_file.startswith(('__init__', 'payload_base')) or not input_file.endswith('.py'):
        continue

    full_import = ['streamalert', 'classifier', 'payload', os.path.splitext(input_file)[0]]

    importlib.import_module('.'.join(full_import))

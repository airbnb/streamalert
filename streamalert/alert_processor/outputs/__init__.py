"""Initialize logging for the alert processor."""
import importlib
import os

# Import all files containing subclasses of OutputDispatcher, skipping the common base class
for output_file in os.listdir(os.path.dirname(__file__)):
    # Skip the common base file and any non-py files
    if output_file.startswith(('__init__', 'output_base')) or not output_file.endswith('.py'):
        continue

    full_import = ['streamalert', 'alert_processor', 'outputs', os.path.splitext(output_file)[0]]

    importlib.import_module('.'.join(full_import))

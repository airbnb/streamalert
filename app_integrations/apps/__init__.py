"""Create some package level items to make this nicer to use"""
import importlib
import os

# Import all files containing subclasses of AppIntegration, skipping the common base class
for app_file in os.listdir(os.path.dirname(__file__)):
    # Skip the common base file and any non-py files
    if app_file.startswith(('__init__', 'app_base')) or not app_file.endswith('.py'):
        continue

    full_import = ['app_integrations', 'apps', os.path.splitext(app_file)[0]]

    importlib.import_module('.'.join(full_import))

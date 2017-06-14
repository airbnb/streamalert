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

import importlib
import os

from stream_alert.rule_processor.handler import StreamAlert

modules_to_import = set()
# walk the rules directory to dymanically import
for root, dirs, files in os.walk('rules/'):
    # ignore old rule files and helpers
    if root in ['rules/helpers', 'rules/']:
        continue
    # ignore __init__.py files
    filtered_files = filter(lambda x: not x.startswith('.') and
                                      not x.endswith('.pyc') and
                                      not x.startswith('__init__'), files)
    for import_file in filtered_files:
        package_path = root.replace('/', '.')
        import_module = os.path.splitext(import_file)[0]
        modules_to_import.add('{}.{}'.format(package_path, import_module))

for module_name in modules_to_import:
    importlib.import_module(module_name)

def handler(event, context):
    """Main Lambda handler function"""
    StreamAlert(context).run(event)

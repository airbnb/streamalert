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
for folder in ('matchers/', 'rules/'):
    for root, dirs, files in os.walk(folder):
        filtered_files = filter(lambda x: not x.startswith('.') and
                                          not x.endswith('.pyc') and
                                          not x.startswith('__init__'),
                                          files)
        for import_file in filtered_files:
            # Greater than two because that indicates there's only one folder
            if len(root.split('/')) > 2:
                package_path = root.replace('/', '.')
            else:
                package_path = root.rstrip('/')
            import_module = os.path.splitext(import_file)[0]
            print package_path, import_module
            if package_path and import_module:
                modules_to_import.add('{}.{}'.format(package_path, import_module))

print modules_to_import
for module_name in modules_to_import:
    importlib.import_module(module_name)

def handler(event, context):
    """Main Lambda handler function"""
    StreamAlert(context).run(event)

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
import importlib
import os

from stream_alert.rule_processor.handler import StreamAlert


def _python_rule_paths():
    """Yields all .py files in matchers/ and rules/."""
    # 'matchers' and 'rules' are top-level folders, both in the repo (when testing)
    # and in the generated Lambda packages.
    for folder in ('matchers', 'rules'):
        for root, _, files in os.walk(folder):
            for file_name in files:
                if file_name.endswith('.py') and not file_name.startswith('__'):
                    yield os.path.join(root, file_name)


def _path_to_module(path):
    """Convert a Python rules file path to an importable module name.

    For example, "rules/community/cloudtrail_critical_api_calls.py" becomes
    "rules.community.cloudtrail_critical_api_calls"

    Raises:
        NameError if a '.' appears anywhere in the path except the file extension.
    """
    base_name = os.path.splitext(path)[0]
    if '.' in base_name:
        raise NameError('Python file {} cannot be imported because of "." in the name', path)
    return os.path.splitext(path)[0].replace('/', '.')


def _import_rules():
    """Dynamically import all rules files."""
    for path in _python_rule_paths():
        importlib.import_module(_path_to_module(path))


_import_rules()


def handler(event, context):
    """Main Lambda handler function"""
    StreamAlert(context).run(event)

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
import importlib
import os


def import_folders(*paths):
    """Dynamically import all rules files.

    Args:
        *paths (string): Variable length tuple of paths from within which any
            .py files should be imported
    """
    for path in _python_file_paths(*paths):
        importlib.import_module(_path_to_module(path))


def _python_file_paths(*paths):
    """Yields all .py files in the passed paths

    Args:
        *paths (string): Variable length tuple of paths from within which any
            .py files should be imported

    Yields:
        str: Relative path to .py file to me imported using importlib
    """
    for folder in paths:
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
        raise NameError(f'Python file "{path}" cannot be imported because of "." in the name')

    return base_name.replace('/', '.')

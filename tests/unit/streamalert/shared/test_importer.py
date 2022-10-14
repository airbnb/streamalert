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
# pylint: disable=protected-access

from unittest.mock import call, patch

import pytest
from pyfakefs import fake_filesystem_unittest

from streamalert.shared.importer import (_path_to_module, _python_file_paths,
                                         import_folders)


class RuleImportTest(fake_filesystem_unittest.TestCase):
    """Test rule import logic with a mocked filesystem."""

    # pylint: disable=protected-access

    def setUp(self):
        self.setUpPyfakefs()

        # Add rule and matcher files which should be imported.
        self.fs.create_file('matchers/default.py')
        self.fs.create_file('rules/example.py')
        self.fs.create_file('rules/community/cloudtrail/critical_api.py')

        # Add other files which should NOT be imported.
        self.fs.create_file('matchers/README.md')
        self.fs.create_file('rules/__init__.py')
        self.fs.create_file('rules/example.pyc')
        self.fs.create_file('rules/community/REVIEWERS')

    @staticmethod
    def test_python_rule_paths():
        """Rule - Python File Paths"""
        result = set(_python_file_paths('matchers', 'rules'))
        expected = {
            'matchers/default.py', 'rules/example.py', 'rules/community/cloudtrail/critical_api.py'
        }
        assert expected == result

    @staticmethod
    def test_path_to_module():
        """Rule - Path to Module"""
        assert 'name' == _path_to_module('name.py')
        assert 'a.b.c.name' == _path_to_module('a/b/c/name.py')

    @staticmethod
    def test_path_to_module_invalid():
        """Rule - Path to Module, Raises Exception"""
        with pytest.raises(NameError):
            _path_to_module('a.b.py')

        with pytest.raises(NameError):
            _path_to_module('a/b/old.name.py')

    @staticmethod
    @patch('importlib.import_module')
    def test_import_rules(mock_import):
        """Rule - Import Folders"""
        import_folders('matchers', 'rules')
        mock_import.assert_has_calls([
            call('matchers.default'),
            call('rules.example'),
            call('rules.community.cloudtrail.critical_api')
        ],
            any_order=True)

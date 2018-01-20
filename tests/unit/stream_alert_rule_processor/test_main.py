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
from mock import call, patch
from nose.tools import assert_equal, assert_raises
from pyfakefs import fake_filesystem_unittest

from stream_alert.rule_processor import main


class RuleImportTest(fake_filesystem_unittest.TestCase):
    """Test rule import logic with a mocked filesystem."""
    # pylint: disable=protected-access

    def setUp(self):
        self.setUpPyfakefs()

        # Add rules files which should be imported.
        self.fs.CreateFile('matchers/matchers.py')
        self.fs.CreateFile('rules/example.py')
        self.fs.CreateFile('rules/community/cloudtrail/critical_api.py')

        # Add other files which should NOT be imported.
        self.fs.CreateFile('matchers/README')
        self.fs.CreateFile('rules/__init__.py')
        self.fs.CreateFile('rules/example.pyc')
        self.fs.CreateFile('rules/community/REVIEWERS')

    def tearDown(self):
        self.tearDownPyfakefs()

    @staticmethod
    def test_python_rule_paths():
        """Rule Processor Main - Find rule paths"""
        result = set(main._python_rule_paths())
        expected = {
            'matchers/matchers.py',
            'rules/example.py',
            'rules/community/cloudtrail/critical_api.py'
        }
        assert_equal(expected, result)

    @staticmethod
    def test_path_to_module():
        """Rule Processor Main - Convert rule path to module name"""
        assert_equal('name', main._path_to_module('name.py'))
        assert_equal('a.b.c.name', main._path_to_module('a/b/c/name.py'))

    @staticmethod
    def test_path_to_module_invalid():
        """Rule Processor Main - Raise NameError for invalid Python filename."""
        assert_raises(NameError, main._path_to_module, 'a.b.py')
        assert_raises(NameError, main._path_to_module, 'a/b/old.name.py')

    @staticmethod
    @patch.object(main, 'importlib')
    def test_import_rules(mock_importlib):
        """Rule Processor Main - Import all rule modules."""
        main._import_rules()
        mock_importlib.assert_has_calls([
            call.import_module('matchers.matchers'),
            call.import_module('rules.example'),
            call.import_module('rules.community.cloudtrail.critical_api')
        ], any_order=True)

    @staticmethod
    @patch.object(main, 'StreamAlert')
    def test_handler(mock_stream_alert):
        """Rule Processor Main - Handler is invoked"""
        main.handler('event', 'context')
        mock_stream_alert.assert_has_calls([
            call('context'),
            call().run('event')
        ])

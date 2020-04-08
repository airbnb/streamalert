"""
Copyright 2017-present Airbnb, Inc.

Licensed under the Apache License, Version 2.0 (the 'License');
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an 'AS IS' BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from mock import Mock

from nose.tools import assert_equal, nottest
from pyfakefs import fake_filesystem_unittest

from streamalert_cli.test.event_file import TestEventFile
from streamalert_cli.test.results import TestResult
from tests.unit.streamalert_cli.test.helpers import (
    basic_test_event_data,
    basic_test_file_json,
)

# Keep nose from trying to treat these as tests
TestEventFile = nottest(TestEventFile)
TestResult = nottest(TestResult)


class TestTestEventFile(fake_filesystem_unittest.TestCase):
    """Test the TestEventFile class"""

    _DEFAULT_EVENT_PATH = 'rules/community/unit_test/file.json'

    def setUp(self):
        self.setUpPyfakefs()

        # Create a single test event file
        self.fs.create_file(
            self._DEFAULT_EVENT_PATH,
            contents=basic_test_file_json()
        )

    @staticmethod
    def _mock_classified_result():
        # log_schema_type is used to validate a classification result
        return Mock(log_schema_type='misc_log_type')

    def _fake_result(self, passed):
        # pylint: disable=protected-access
        result = TestResult(0, basic_test_event_data())
        result._classified_result = self._mock_classified_result() if passed else False
        return result

    def test_stringer(self):
        """StreamAlert CLI - TestEventFile Stringer"""
        # pylint: disable=protected-access
        event = TestEventFile(self._DEFAULT_EVENT_PATH)
        event._results.append(self._fake_result(True))

        expected_stringer = (
            '\033[4m\nFile: rules/community/unit_test/file.json\n\033[0m'
            '\nTest #01: \033[0;32;1mPass\033[0m'
        )

        assert_equal(str(event), expected_stringer)

    def test_stringer_with_error(self):
        """StreamAlert CLI - TestEventFile Stringer, Error"""
        event = TestEventFile(self._DEFAULT_EVENT_PATH)
        event.error = 'Bad thing happened'

        expected_stringer = (
            '\033[4m\nFile: rules/community/unit_test/file.json\n\033[0m'
            '\n\033[0;31;1mBad thing happened\033[0m'
        )

        assert_equal(str(event), expected_stringer)

    def test_bool(self):
        """StreamAlert CLI - TestEventFile Bool"""
        # pylint: disable=protected-access
        event = TestEventFile(self._DEFAULT_EVENT_PATH)

        assert_equal(bool(event), False)

        event._results.append(self._fake_result(True))

        assert_equal(bool(event), True)

    def test_passed(self):
        """StreamAlert CLI - TestEventFile Passed"""
        # pylint: disable=protected-access
        event = TestEventFile(self._DEFAULT_EVENT_PATH)
        event._results.append(self._fake_result(True))

        assert_equal(event.passed, True)

    def test_failed(self):
        """StreamAlert CLI - TestEventFile Failed"""
        # pylint: disable=protected-access
        event = TestEventFile(self._DEFAULT_EVENT_PATH)
        event._results.append(self._fake_result(False))

        assert_equal(event.failed, True)

    def test_load_file_valid(self):
        """StreamAlert CLI - TestEventFile Load File, Valid"""
        event = TestEventFile(self._DEFAULT_EVENT_PATH)
        value = list(event.load_file())

        assert_equal(len(value), 1)
        assert_equal(event.error, None)

    def test_load_file_invalid_json(self):
        """StreamAlert CLI - TestEventFile Load File, Invalid JSON"""
        file_path = 'rules/community/unit_test/bad-file.json'
        self.fs.create_file(file_path, contents='invalid json string')

        event = TestEventFile(file_path)
        list(event.load_file())

        assert_equal(event.error, 'Test event file is not valid JSON')

    def test_load_file_invalid_format(self):
        """StreamAlert CLI - TestEventFile Load File, Invalid Format"""
        file_path = 'rules/community/unit_test/bad-file.json'
        self.fs.create_file(file_path, contents='{"bad": "format"}')

        event = TestEventFile(file_path)
        list(event.load_file())

        assert_equal(
            event.error,
            'Test event file is improperly formatted; events should be in a list'
        )

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
import json

from streamalert.shared.logger import get_logger
from streamalert_cli.test.format import format_red, format_underline
from streamalert_cli.test.results import TestResult

LOGGER = get_logger(__name__)


class TestEventFile:
    """TestEventFile handles caching results of test events within a test file"""
    def __init__(self, full_path):
        self._full_path = full_path
        self._results = []  # type: list[streamalert_cli.test.results.TestResult]
        self.error = None

    def __bool__(self):
        return bool(self._results)

    def __str__(self):
        output = [format_underline(f'\nFile: {self._full_path}\n')]

        if self.error:
            output.append(format_red(self.error))
        else:
            output.extend(iter(self._results))
        return '\n'.join(str(item) for item in output)

    @property
    def path(self):
        return self._full_path

    @property
    def should_print(self):
        return any(not result.suppressed for result in self._results)

    @property
    def all_passed(self):
        return self.passed == len(self._results)

    @property
    def passed(self):
        return sum(1 for result in self._results if not result.suppressed and result.passed)

    @property
    def failed(self):
        return sum(not (result.suppressed or result.passed) for result in self._results)

    def load_file(self):
        """Helper to json load the contents of a file with some error handling

        Test files should be formatted as:

        [
            {
                "data": {},
                "description": "...",
                "...": "..."
            }
        ]

        Returns:
            dict: Loaded JSON from test event file
        """
        with open(self._full_path, encoding="utf-8") as test_event_file:
            try:
                data = json.load(test_event_file)
            except (ValueError, TypeError):
                self.error = 'Test event file is not valid JSON'
                return

            if not isinstance(data, list):
                self.error = 'Test event file is improperly formatted; events should be in a list'
                return

            yield from data

    def process_file(self, config, verbose, with_rules):
        for idx, event in enumerate(self.load_file()):
            test_result = TestResult(idx, event, verbose, with_rules)
            self._results.append(test_result)
            if test_result.prepare(config):
                yield test_result

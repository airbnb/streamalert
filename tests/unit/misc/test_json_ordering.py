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
# pylint: disable=attribute-defined-outside-init,no-self-use,protected-access
import json
import difflib
import os

from collections import OrderedDict
from nose.tools import assert_equal

CONF_LOGS_FILE = os.path.join(os.path.dirname(__file__), '../../../conf/logs.json')


class TestLogsJsonFile(object):
    """
    Tests that the conf.json file is formatted properly and is sorted alphabetically
    on the top-level key
    """

    def test_is_sorted_alphabetically(self):
        """Misc - Configuration Files - Keys are sorted alphabetically"""
        with open(CONF_LOGS_FILE, 'r') as infile:
            original_text = infile.read().strip()

        # Load the JSON document using OrderedDict so that it preserves original ordering
        schema = json.loads(original_text, object_pairs_hook=OrderedDict)
        ordered_schema = OrderedDict(sorted(schema.items(), key=lambda k: k[0]))
        expected_text = json.dumps(ordered_schema, indent=2, separators=(',', ': ')).strip()

        original_text_lines = original_text.splitlines(1)
        expected_text_lines = expected_text.splitlines(1)

        diff = difflib.unified_diff(original_text_lines, expected_text_lines)
        diffs = list(diff)  # Extract values out of the generator to prevent mistakes later

        failure_message = 'JSON Document is malformed or out of order: {}'.format(''.join(diffs))

        assert_equal(len(diffs), 0, failure_message)

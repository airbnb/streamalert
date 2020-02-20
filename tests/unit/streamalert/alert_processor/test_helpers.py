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
from nose.tools import assert_equal

from streamalert.alert_processor.helpers import elide_string_middle


def test_elide_string_middle():
    """Alert Processor - Helpers - String Truncation"""
    alphabet = 'abcdefghijklmnopqrstuvwxyz'

    # String shortened
    assert_equal('ab ... yz', elide_string_middle(alphabet, 10))
    assert_equal('abcde ... vwxyz', elide_string_middle(alphabet, 15))
    assert_equal('abcdefg ... tuvwxyz', elide_string_middle(alphabet, 20))
    assert_equal('abcdefghij ... qrstuvwxyz', elide_string_middle(alphabet, 25))

    # String unchanged
    assert_equal(alphabet, elide_string_middle(alphabet, 26))
    assert_equal(alphabet, elide_string_middle(alphabet, 50))

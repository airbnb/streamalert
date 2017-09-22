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
# pylint: disable=protected-access
from nose.tools import (
    assert_list_equal,
    assert_equal,
    assert_is_instance
)

import stream_alert.rule_processor.threat_intel as threat_intel

class TestThreatIntel(object):
    """Test class for ThreatIntel"""
    def __init__(self):
        self.threat_intel = None

    def setup(self):
        """Setup before each test case"""
        self.threat_intel = threat_intel.ThreatIntel('tests/unit/fixtures')

    def test_read_compressed_files(self):
        """TheatIntel - Read compressed csv.gz files into a dictionary"""
        intelligence = self.threat_intel.read_compressed_files()
        assert_is_instance(intelligence, dict)
        assert_list_equal(sorted(intelligence.keys()),
                          sorted(['domain', 'md5', 'ip']))
        assert_equal(len(intelligence['domain']), 10)
        assert_equal(len(intelligence['md5']), 10)
        assert_equal(len(intelligence['ip']), 10)

    def test_read_compressed_files_not_exist(self):
        """ThreatIntel - Location of intelligence files not exist"""
        self.threat_intel = threat_intel.ThreatIntel('not/exist/dir')
        intelligence = self.threat_intel.read_compressed_files()
        assert_equal(intelligence, None)

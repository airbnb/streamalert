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
    assert_is_instance,
    assert_items_equal
)

from stream_alert.rule_processor.threat_intel import StreamThreatIntel

class TestStreamStreamThreatIntel(object):
    """Test class for StreamThreatIntel"""
    def setup(self):
        """Setup before each method"""
        # Clear out the cached matchers and rules to avoid conflicts with production code
        StreamThreatIntel._StreamThreatIntel__intelligence.clear()  # pylint: disable=no-member
        StreamThreatIntel._StreamThreatIntel__config.clear()  # pylint: disable=no-member

    def test_read_compressed_files(self):
        """Theat Intel - Read compressed csv.gz files into a dictionary"""
        intelligence = StreamThreatIntel.read_compressed_files('tests/unit/fixtures')
        assert_is_instance(intelligence, dict)
        assert_list_equal(sorted(intelligence.keys()),
                          sorted(['domain', 'md5', 'ip']))
        assert_equal(len(intelligence['domain']), 10)
        assert_equal(len(intelligence['md5']), 10)
        assert_equal(len(intelligence['ip']), 10)

    def test_read_compressed_files_not_exist(self):
        """Threat Intel - Location of intelligence files not exist"""
        # self.threat_intel = ti.StreamThreatIntel('not/exist/dir')
        intelligence = StreamThreatIntel.read_compressed_files('not/exist/dir')
        assert_equal(intelligence, None)

    def test_load_intelligence(self):
        """Threat Intel - Load intelligence to memory"""
        test_config = {
            'threat_intel': {
                'enabled': True,
                'mapping': {
                    'sourceAddress': 'ip',
                    'destinationDomain': 'domain',
                    'fileHash': 'md5'
                }
            }
        }
        StreamThreatIntel.load_intelligence(test_config, 'tests/unit/fixtures')
        intelligence = StreamThreatIntel._StreamThreatIntel__intelligence # pylint: disable=no-member
        expected_keys = ['domain', 'md5', 'ip']
        assert_items_equal(intelligence.keys(), expected_keys)
        assert_equal(len(intelligence['domain']), 10)
        assert_equal(len(intelligence['md5']), 10)
        assert_equal(len(intelligence['ip']), 10)

    def test_do_not_load_intelligence(self):
        """Threat Intel - Do not load intelligence to memory when it is disabled"""
        test_config = {
            'threat_intel': {
                'enabled': False,
                'mapping': {
                    'sourceAddress': 'ip',
                    'destinationDomain': 'domain',
                    'fileHash': 'md5'
                }
            }
        }
        StreamThreatIntel.load_intelligence(test_config, 'tests/unit/fixtures')
        intelligence = StreamThreatIntel._StreamThreatIntel__intelligence # pylint: disable=no-member
        assert_equal(len(intelligence), 0)

    def test_get_intelligence(self):
        """Threat Intel - get intelligence dictionary"""
        test_config = {
            'threat_intel': {
                'enabled': True,
                'mapping': {
                    'sourceAddress': 'ip',
                    'destinationDomain': 'domain',
                    'fileHash': 'md5'
                }
            }
        }
        StreamThreatIntel.load_intelligence(test_config, 'tests/unit/fixtures')
        intelligence = StreamThreatIntel.get_intelligence()
        expected_keys = ['domain', 'md5', 'ip']
        assert_items_equal(intelligence.keys(), expected_keys)
        assert_equal(len(intelligence['domain']), 10)
        assert_equal(len(intelligence['md5']), 10)
        assert_equal(len(intelligence['ip']), 10)

    def test_get_config(self):
        """Threat Intel - get intelligence dictionary"""
        test_config = {
            'threat_intel': {
                'enabled': True,
                'mapping': {
                    'sourceAddress': 'ip',
                    'destinationDomain': 'domain',
                    'fileHash': 'md5'
                }
            }
        }
        StreamThreatIntel.load_intelligence(test_config, 'tests/unit/fixtures')
        datatypes_ioc_mapping = StreamThreatIntel.get_config()
        expected_keys = ['sourceAddress', 'destinationDomain', 'fileHash']
        assert_items_equal(datatypes_ioc_mapping.keys(), expected_keys)
        assert_equal(datatypes_ioc_mapping['sourceAddress'], 'ip')
        assert_equal(datatypes_ioc_mapping['destinationDomain'], 'domain')
        assert_equal(datatypes_ioc_mapping['fileHash'], 'md5')

    def test_no_config_loaded(self):
        """Threat Intel - No datatypes_ioc_mapping config loaded if it is disabled"""
        test_config = {
            'threat_intel': {
                'enabled': False,
                'mapping': {
                    'sourceAddress': 'ip',
                    'destinationDomain': 'domain',
                    'fileHash': 'md5'
                }
            }
        }
        StreamThreatIntel.load_intelligence(test_config, 'tests/unit/fixtures')
        datatypes_ioc_mapping = StreamThreatIntel.get_config()
        assert_equal(len(datatypes_ioc_mapping), 0)
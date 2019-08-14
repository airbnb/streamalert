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
import copy
from datetime import datetime, timedelta
import json

from nose.tools import (
    assert_equal,
    assert_false,
    assert_is_instance,
    assert_not_in,
    assert_raises,
    assert_true
)

from stream_alert.shared.lookup_tables.configuration import LookupTablesConfiguration


class TestLookupTable(object):
    """Test shared LookupTablesConfiguration class."""

    # pylint: disable=no-self-use,protected-access,too-many-public-methods

    @staticmethod
    def _basic_configuration():
        return {
            "lookup_tables": {
                "enabled": True,
                "tables": {
                    "resource_map_prototype": {
                        "driver": "s3",
                        "bucket": "airbnb.sample.lookuptable",
                        "key": "resource_map.gz",
                        "cache_refresh_minutes": 10,
                        "compression": "gzip"
                    },
                    "resource_map_dynamodb": {
                        "driver": "dynamodb",
                        "table": "some_table_name",
                        "partition_key": "MyPartitionKey",
                        "value_key": "MyValueKey",
                        "cache": {
                            "refresh_minutes": 2,
                            "maximum_keys": 10
                        }
                    }
                }
            }
        }

    def test_configuration_enabled(self):
        """LookupTable - Basic Configuration - Enabled"""
        config = LookupTablesConfiguration(self._basic_configuration())
        assert_true(config.is_enabled)

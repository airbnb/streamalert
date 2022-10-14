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

from streamalert.shared.lookup_tables.configuration import \
    LookupTablesConfiguration


class TestLookupTablesConfiguration:
    """Test shared LookupTablesConfiguration class."""

    # pylint: disable=no-self-use,protected-access,too-many-public-methods

    @staticmethod
    def _basic_configuration():
        return {
            'lookup_tables': {
                'enabled': True,
                'tables': {
                    'resource_map_prototype': {
                        'driver': 's3',
                        'bucket': 'airbnb.sample.lookuptable',
                        'key': 'resource_map.gz',
                        'cache_refresh_minutes': 10,
                        'compression': 'gzip'
                    },
                    'resource_map_dynamodb': {
                        'driver': 'dynamodb',
                        'table': 'some_table_name',
                        'partition_key': 'MyPartitionKey',
                        'value_key': 'MyValueKey',
                        'cache': {
                            'refresh_minutes': 2,
                            'maximum_keys': 10
                        }
                    }
                }
            }
        }

    def test_configuration_enabled(self):
        """LookupTablesConfiguration - Basic Configuration - Enabled"""
        config = LookupTablesConfiguration(self._basic_configuration())
        assert config.is_enabled

    def test_configuration_table_names(self):
        """LookupTablesConfiguration - Basic Configuration - Table Names"""
        config = LookupTablesConfiguration(self._basic_configuration())
        assert (
            config.table_names ==
            ['resource_map_prototype', 'resource_map_dynamodb'])

    def test_configuration_table_configurations(self):
        """LookupTablesConfiguration - Basic Configuration - Table Configurations"""
        config = LookupTablesConfiguration(self._basic_configuration())
        assert config.table_configurations['resource_map_dynamodb']['driver'] == 'dynamodb'

    def test_configuration_empty_configuration_not_enabled(self):
        """LookupTablesConfiguration - Empty Configuration - Not Enabled"""
        config = LookupTablesConfiguration({})
        assert not config.is_enabled

    def test_configuration_disabled_configuration(self):
        """LookupTablesConfiguration - Disabled Configuration - Disabled"""
        config = LookupTablesConfiguration({
            'lookup_tables': {
                'enabled': False,
                'tables': {
                    'resource_map_prototype': {
                        'driver': 's3',
                        'bucket': 'airbnb.sample.lookuptable',
                        'key': 'resource_map.gz',
                        'cache_refresh_minutes': 10,
                        'compression': 'gzip'
                    },
                }
            }
        })
        assert not config.is_enabled

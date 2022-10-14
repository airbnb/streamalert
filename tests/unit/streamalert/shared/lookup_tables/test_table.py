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

from streamalert.shared.lookup_tables.drivers_factory import \
    construct_persistence_driver
from streamalert.shared.lookup_tables.table import LookupTable


class TestLookupTable:
    """Test shared LookupTable class."""

    # pylint: disable=no-self-use,protected-access,too-many-public-methods
    def __init__(self):
        self._driver = None
        self._table = None

    def setup(self):
        config = {'driver': 'ephemeral'}
        self._driver = construct_persistence_driver(config)
        self._driver.set('this', 'that')
        self._driver.set('those', {'theys': 'thens'})
        self._table = LookupTable('my-table', self._driver, config)

    def test_table_nonexistent(self):
        """LookupTable - Basic Table - Nonexistent Key None Default"""
        assert self._table.get('nonexistent_key') is None

    def test_table_nonexistent_default(self):
        """LookupTable - Basic Table - Nonexistent Key With Default"""
        assert self._table.get('nonexistent_key', '1') == '1'

    def test_table_existent(self):
        """LookupTable - Basic Table - Existent"""
        assert self._table.get('this', '?') == 'that'

    def test_table_driver_id(self):
        """LookupTable - Basic Table - Driver Id"""
        assert self._table.driver_id == 'ephemeral:1'

    def test_table_driver_type(self):
        """LookupTable - Basic Table - Driver Type"""
        assert self._table.driver_type == 'ephemeral'

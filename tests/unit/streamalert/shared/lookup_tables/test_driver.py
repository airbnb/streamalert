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

import pytest

from streamalert.shared.lookup_tables.drivers import (EphemeralDriver,
                                                      NullDriver)
from streamalert.shared.lookup_tables.drivers_factory import \
    construct_persistence_driver
from streamalert.shared.lookup_tables.errors import \
    LookupTablesConfigurationError


class TestEphemeralDriver:
    """Test shared EphemeralDriver"""

    # pylint: disable=no-self-use,protected-access,too-many-public-methods
    def __init__(self):
        self._driver = None

    def setup(self):
        self._driver = construct_persistence_driver({'driver': 'ephemeral'})
        self._driver.set('this', 'that')
        self._driver.set('those', {'theys': 'thens'})

    def test_driver_type(self):
        """LookupTable - Drivers - Ephemeral Driver - Type"""
        assert isinstance(self._driver, EphemeralDriver)

    def test_driver_nonexistent(self):
        """LookupTable - Drivers - Ephemeral Driver - Nonexistent Key None Default"""
        assert self._driver.get('nonexistent_key') is None

    def test_driver_nonexistent_default(self):
        """LookupTable - Drivers - Ephemeral Driver - Nonexistent Key With Default"""
        assert self._driver.get('nonexistent_key') is None

    def test_driver_existent(self):
        """LookupTable - Drivers - Ephemeral Driver - Existent"""
        assert self._driver.get('those') == {'theys': 'thens'}

    def test_table_driver_id(self):
        """LookupTable - Drivers - Ephemeral Driver - Id"""
        assert self._driver.id == 'ephemeral:1'

    def test_table_driver_type(self):
        """LookupTable - Drivers - Ephemeral Driver - Type"""
        assert self._driver.driver_type == 'ephemeral'


class TestNullDriver:
    """... purely for test coverage"""

    # pylint: disable=no-self-use,protected-access,too-many-public-methods
    def __init__(self):
        self._driver = None

    def setup(self):
        self._driver = construct_persistence_driver({'driver': 'null'})
        self._driver.set('this', 'that')
        self._driver.set('those', {'theys': 'thens'})

    def test_driver_type(self):
        """LookupTable - Drivers - Null Driver - Type"""
        assert isinstance(self._driver, NullDriver)

    def test_driver_nonexistent(self):
        """LookupTable - Drivers - Null Driver - Nonexistent Key None Default"""
        assert self._driver.get('nonexistent_key') is None

    def test_driver_nonexistent_default(self):
        """LookupTable - Drivers - Null Driver - Nonexistent Key With Default"""
        assert self._driver.get('nonexistent_key') is None

    def test_driver_existent(self):
        """LookupTable - Drivers - Null Driver - Existent"""
        assert self._driver.get('those') is None

    def test_table_driver_id(self):
        """LookupTable - Drivers - Null Driver - Id"""
        assert self._driver.id == 'null:1'

    def test_table_driver_type(self):
        """LookupTable - Drivers - Null Driver - Type"""
        assert self._driver.driver_type == 'null'


def test_construct_persistence_driver_nope():
    """LookupTable - Drivers - construct_persistence_driver - Nonexistent"""
    pytest.raises(LookupTablesConfigurationError, construct_persistence_driver, {})

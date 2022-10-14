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
from datetime import datetime

from streamalert.shared.lookup_tables.cache import DriverCache


class TestDriverCache:
    """
    Tests the S3Driver

    This was largely ported over from test_lookup_tables.py from the old implementation.
    """
    # pylint: disable=protected-access,attribute-defined-outside-init,no-self-use

    def setup(self):
        self._cache = DriverCache()

    def test_base_case(self):
        """LookupTables - DriverCache - Base Case"""
        assert not self._cache.has('?')
        assert self._cache.get('?') is None
        assert self._cache.get('?', 'default') == 'default'

    def test_set_has_get_case(self):
        """LookupTables - DriverCache - Set Has Get"""
        assert not self._cache.has('key')
        self._cache.set('key', 'asdf', 1)
        assert self._cache.has('key')
        assert self._cache.get('key') == 'asdf'

    def test_set_has_get_time_machine(self):
        """LookupTables - DriverCache - Set Has Get with Time Machine"""
        self._cache._clock.time_machine(datetime(year=2000, month=1, day=1))

        assert not self._cache.has('key')
        self._cache.set('key', 'asdf', 1)
        assert self._cache.has('key')
        assert self._cache.get('key') == 'asdf'

    def test_set_has_get_time_machine_past_ttl(self):
        """LookupTables - DriverCache - Set Has Get with Time Machine - Past ttl"""
        self._cache._clock.time_machine(datetime(year=2000, month=1, day=1))

        assert not self._cache.has('key')
        self._cache.set('key', 'asdf', 1)
        self._cache._clock.time_machine(datetime(year=2000, month=1, day=1, minute=1, second=1))
        assert not self._cache.has('key')

    def test_set_has_get_time_machine_at_ttl(self):
        """LookupTables - DriverCache - Set Has Get with Time Machine - At ttl"""
        self._cache._clock.time_machine(datetime(year=2000, month=1, day=1))

        assert not self._cache.has('key')
        self._cache.set('key', 'asdf', 1)
        self._cache._clock.time_machine(datetime(year=2000, month=1, day=1, minute=1))
        assert self._cache.has('key')

    def test_set_blank(self):
        """LookupTables - DriverCache - set_blank with Time Machine - At ttl"""
        self._cache._clock.time_machine(datetime(year=2000, month=1, day=1))

        assert not self._cache.has('key')
        self._cache.set_blank('key', 1)
        assert self._cache.has('key')
        assert self._cache.get('key', 'default') == 'default'

    def test_set_blank_with_existing(self):
        """LookupTables - DriverCache - set_blank with Time Machine on existing - At ttl"""
        self._cache._clock.time_machine(datetime(year=2000, month=1, day=1))

        assert not self._cache.has('key')
        self._cache.set('key', 'nothing', 1)
        assert self._cache.has('key')
        self._cache.set_blank('key', 1)
        assert self._cache.has('key')
        assert self._cache.get('key', 'default') == 'default'

    def test_set_blank_past_ttl(self):
        """LookupTables - DriverCache - set_blank with Time Machine - At ttl"""
        self._cache._clock.time_machine(datetime(year=2000, month=1, day=1))

        assert not self._cache.has('key')
        self._cache.set_blank('key', 1)

        self._cache._clock.time_machine(datetime(year=2000, month=1, day=1, minute=1, second=1))

        assert not self._cache.has('key')

    def test_set_all(self):
        """LookupTables - DriverCache - setall"""
        self._cache._clock.time_machine(datetime(year=2000, month=1, day=1))

        assert not self._cache.has('key')

        self._cache.setall({
            'key': 'value',
            'dog': 'cat',
            'up': 'down',
            'space': 'hamster',
        }, 1)

        assert self._cache.has('space')
        assert self._cache.has('up')

    def test_cache_eviction(self):
        """LookupTables - DriverCache - set with cache eviction"""
        cache = DriverCache(maximum_key_count=5)

        assert len(cache._data) == 0

        cache.set('asdf1', 'cat', 1)
        cache.set('asdf2', 'cat', 1)
        cache.set('asdf3', 'cat', 1)
        cache.set('asdf4', 'cat', 1)
        cache.set('asdf5', 'always cats', 1)

        assert len(cache._data) == 5

        cache.set('asdf6', 'definitely always cats', 1)

        assert len(cache._data) == 5

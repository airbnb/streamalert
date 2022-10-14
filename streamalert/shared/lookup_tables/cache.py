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
import copy
import random
from datetime import datetime, timedelta

from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


class DriverCache:
    """
    A class that is responsible for caching objects in-memory.

    This class is to intended to be used in the following pattern:

    def get(key, default=None):
        if not cache.has(key):
            try:
                data = load_data(key)
                cache.set(key, data)
            except NoSuchKeyException:
                cache.blank(key)

        return cache.get(key, default)
    """
    def __init__(self, maximum_key_count=0):
        """
        Constructor

        Params:
            maximum_key_count (int)
                The maximum number of keys allowed in this cache before records start getting
                evicted. Eviction is at random. A maximum key count of 0 or less means the cache
                size is unlimited and will perform no evictions (dangerous!!!)
        """
        self._data = {}
        self._ttls = {}
        self._clock = DriverCacheClock()

        self._maximum_key_count = maximum_key_count

    def ttl(self, key):
        """
        Returns the datetime time-to-live of the requested key.

        Params:
            key (str)

        Returns:
            datetime|None
        """
        return self._ttls.get(key, None)

    def has(self, key):
        """
        Returns FALSE when the requested key has either not been loaded yet, or has reached the end
        of its caching ttl.

        Params:
            key (string)

        Returns:
            bool
        """
        return self._clock.utcnow() <= self._ttls[key] if key in self._ttls else False

    def get(self, key, default=None):
        """
        Returns the currently cached value at the key, DISREGARDING the ttl.

        Use has() to check if the key is over the ttl.

        Params:
            key (str)
            default (mixed)

        Returns:
            mixed
        """
        return self._data.get(key, default)

    def set(self, key, value, ttl_minutes):
        """
        Sets the given value to the requested key. The key expires after ttl_minutes, relative to
        "now", as defined by the DriverCacheClock.

        Params:
            key (str)
            value (mixed)
            ttl_minutes (int)
        """
        if 0 < self._maximum_key_count < len(self._data) + 1:
            # Cache is too full, evict a random record
            # The reason for RANDOM eviction is that for a LRU cache replacement policy,
            # Cache pollution can occur for Lambdas that experience extremely deterministic
            # key loading orders.
            selected_key = random.choice(list(self._ttls.keys()))
            del self._ttls[selected_key]
            del self._data[selected_key]

        self._data[key] = value
        self._ttls[key] = self._clock.utcnow() + timedelta(minutes=ttl_minutes)

    def set_blank(self, key, ttl_minutes):
        """
        When loading a key that is discovered to be blank, instead of setting a 'None' value into
        the cache, we set nothing into the cache and mark the TTL anyway.

        This allows get() to properly return default values, and prevents us from doing redundant
        queries on keys that are known to be nonexistent.

        Params:
            key (str)
            ttl_minutes (int)
        """
        if key in self._data:
            del self._data[key]
        self._ttls[key] = self._clock.utcnow() + timedelta(minutes=ttl_minutes)

    def setall(self, keyvalue_data, ttl_minutes):
        """
        As set(), but replaces the entire set of currently cached values with a new data set.

        (!) NOTE: This disregards the maximum_key_count option.

        Params:
            keyvalue_data (dict)
            ttl_minutes (int)
        """
        if not keyvalue_data:
            self._data = {}
            self._ttls = {}
            return

        self._data = keyvalue_data
        ttl = self._clock.utcnow() + timedelta(minutes=ttl_minutes)
        for key in keyvalue_data.keys():
            self._ttls[key] = ttl

    def getall(self):
        return copy.copy(self._data)


class DriverCacheClock:
    """
    The DriverCacheClock is a convenient utility that is useful for manipulating time during tests.
    """
    def __init__(self):
        self._time_machine = None

    def utcnow(self):
        """
        Gets the current time

        Returns:
            datetime
        """
        return self._time_machine or datetime.utcnow()

    def time_machine(self, new_datetime):
        """
        Params:
            new_datetime (datetime)
        """
        self._time_machine = new_datetime

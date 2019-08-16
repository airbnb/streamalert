from datetime import datetime, timedelta


class DriverCache(object):
    """
    A class that is responsible for caching objects.

    This class is to intended to be used in the following pattern:

    def get(key, default=None):
        if cache.has(key):
            try:
                data = load_data(key)
                cache.set(key, data)
            except NoSuchKeyException:
                cache.blank(key)

        return cache.get(key, default)
    """

    def __init__(self):
        self._data = {}
        self._ttls = {}
        self._clock = DriverCacheClock()

    def has(self, key):
        """
        Returns FALSE when the requested key has either not been loaded yet, or has reached the end
        of its caching ttl.

        Params:
            key (string)

        Returns:
            bool
        """
        if key not in self._ttls:
            return False

        return self._clock.utcnow() <= self._ttls[key]

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

        Params:
            keyvalue_data (dict)
            ttl_minutes (int)
        """
        self._data = keyvalue_data
        ttl = self._clock.utcnow() + timedelta(minutes=ttl_minutes)
        for key in keyvalue_data.iterkeys():
            self._ttls[key] = ttl


class DriverCacheClock(object):
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
        if self._time_machine:
            return self._time_machine

        return datetime.utcnow()

    def time_machine(self, new_datetime):
        """
        Params:
            new_datetime (datetime)
        """
        self._time_machine = new_datetime

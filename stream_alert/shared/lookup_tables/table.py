class LookupTable(object):
    """
    A single lookup table

    Lookup tables always have a backing layer encapsulated in the Driver.
    """

    def __init__(self, table_name, driver):
        self._table_name = table_name
        self._driver = driver

    @property
    def table_name(self):
        return self._table_name

    def get(self, key, default=None):
        return self._driver.get(key, default)

    def set(self, key, value):
        return self._driver.set(key, value)

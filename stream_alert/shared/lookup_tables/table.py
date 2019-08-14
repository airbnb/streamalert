from stream_alert.shared.logger import get_logger
from stream_alert.shared.lookup_tables.drivers import PersistenceDriver, S3Driver

LOGGER = get_logger(__name__)


class LookupTable(dict):
    """
    A single lookup table

    Lookup tables always have a backing layer encapsulated in the Driver.

    For reverse compatibility reasons, the LookupTable class actually extends and emulates a dict,
    behaving like a container. Through the magic of metaprogramming, we allow all legacy code that
    leverages lookup tables like a dict to continue to ... kind of work*.

    So, when does it fail?

    > Modifications
    This was valid but PROBABLY considered an anti-pattern in LookupTables. Now this will simply
    not work at all, as all of the modification methods are broken.

    > Enumeration of all possible keys
    This is no longer reliable, as there is no guarantee that a Driver (such as DynamoDB) has the
    capability of enumerating all of its keys.

    > Iteration
    This is likely to be a valid use case for many StreamAlert customers, but similar to the case
    with Enumerating all possible keys, this functionality is no longer reliable.
    """
    _driver = None  # type: PersistenceDriver

    def __init__(self, table_name, driver, table_configuration):
        """

        """
        super(dict, self).__init__()

        self._table_name = table_name
        self._table_configuration = table_configuration
        self._driver = driver
        self._initialized = False

    @property
    def table_name(self):
        return self._table_name

    @property
    def driver_id(self):
        return self._driver.id

    def initialize_if_necessary(self):
        if self._initialized:
            return

        self._initialized = True
        self._driver.initialize()

    def get(self, key, default=None):
        self.initialize_if_necessary()
        return self._driver.get(key, default)

    # Below this line are re-implementations of all of the python dict native methods...
    # These methods are likely used by existing StreamAlert deployments. In the interest of
    # reverse-compatibility, this is our best-effort attempt to make sure we don't break pre-
    # August 2019 builds.
    #
    # Notably, DynamoDb was not supported until this (post-August-2019) build. DynamoDb will
    # not support certain access patterns that were originally supported by S3; most notably,
    # enumerating and iterating over all keys available.

    def __getitem__(self, item):
        """
        Support accessing keys on the LookupTable like a dict:

            table = LookupTables.get_table('my_table')
            my_value = table['my_key']
        """
        # There is a subtle difference here; When a dict is missing a key, it will raise a
        # KeyError. In the new implementation, it simply returns None.
        #
        # That being said because there is a warning that highly suggests upgrading to the new
        # access pattern, I believe this is subtle change in behavior is justifiable.
        LOGGER.warn(
            'LookupTable %s: Please use .get(), rather than accessing LookupTables as dicts.',
            self._table_name
        )
        return self.get(item)

    def __iter__(self):
        return self._proxy_call('__iter__')

    def __len__(self):
        return self._proxy_call('__len__')

    def values(self):
        return self._proxy_call('values')

    def items(self):
        return self._proxy_call('items')

    def keys(self):
        return self._proxy_call('keys')

    def __contains__(self, *args):
        return self._proxy_call('__contains__', *args)

    def has_key(self, k):
        return self._proxy_call('has_key', k)

    # Below this line are no-effect methods. They are not likely to be used in the wild due to
    # it being "insensible" to use in this manner.

    def __repr__(self):
        return self._no_effect('__repr__')

    def __setitem__(self, key, value):
        return self._no_effect('__setitem__')

    def __delitem__(self, key):
        return self._no_effect('__delitem__')

    def clear(self):
        return self._no_effect('clear')

    def copy(self):
        return self._no_effect('copy')

    def update(self, *args, **kwargs):
        return self._no_effect('update')

    def pop(self):
        return self._no_effect('pop')

    def __cmp__(self, other):
        return self._no_effect('__cmp__')

    def __unicode__(self):
        return self._no_effect('__unicode__')

    def _no_effect(self, function_name):
        LOGGER.warn(
            'Calling %s on a LookupTable %s has no effect and will not do what you think it does!',
            function_name,
            self._table_name
        )

    def _proxy_call(self, function_name, *args, **kwargs):
        """
        For reverse compatibility reasons, some customers of LookupTables may use old dict-specific
        methods to (for example) loop over the returned dicts. This is valid for the S3 driver
        case, as all keys are loaded into memory up-front:

            table = LookupTables.get_table('my_table')

            for key, value in table.iteritems():
                # ...

        Many of these access patterns are not valid for DynamoDb-type drivers. Even though DynamoDb
        possesses the functionality to iterate over sort keys, we intentional restrict this as
        performing table iterations in LookupTables is considered an anti-pattern.
        """

        if isinstance(self._driver, S3Driver):
            LOGGER.warn(
                (
                    'LookupTable %s: Calling %s() on a LookupTable is not evenly supported '
                    'across all drivers and is considered deprecated functionality.'
                ),
                self._table_name,
                function_name
            )
            self.initialize_if_necessary()

            # Unholy metaprogramming at its finest
            return getattr(
                self._driver.legacy_get_s3_internal_dict(), function_name
            )(*args, **kwargs)

        LOGGER.error(
            (
                'LookupTable %s: It is not valid to call %s() on a LookupTable that is not '
                'backed by s3. Prefer to use .get()'
            ),
            self._table_name,
            function_name
        )
        return []

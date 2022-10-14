from streamalert.shared.config import load_config
from streamalert.shared.logger import get_logger
from streamalert.shared.lookup_tables.configuration import \
    LookupTablesConfiguration
from streamalert.shared.lookup_tables.drivers import NullDriver
from streamalert.shared.lookup_tables.drivers_factory import \
    construct_persistence_driver
from streamalert.shared.lookup_tables.table import LookupTable

LOGGER = get_logger(__name__)


class LookupTables:
    """
    A class primarily responsible for syntactic sugar + application singleton behavior that wraps
    the LookupTablesCore.
    """
    _instance = None  # type: LookupTablesCore

    @classmethod
    def get_instance(cls, config=None, reset=False):
        """
        Returns a singleton instance of LookupTablesCore.

        Params:
            config (dict) OPTIONAL: You can provide this to override default behavior or as an
                optimization. Be careful; once loaded the LookupTables is cached statically
                and future invocations will ignore this config parameter, even when provided.
            reset (bool) OPTIONAL: Flag designating whether or not the cached instance of
                LookupTablesCore should be re-instantiated. Default value is False.

        Returns:
            LookupTablesCore
        """
        if not cls._instance or reset:
            if config is None:
                config = load_config()

            cls._instance = LookupTablesCore(config)
            cls._instance.setup_tables()

        return cls._instance

    @classmethod
    def get(cls, table_name, key, default=None):
        """
        Retrieves the key's value on the requested lookup table. If the given key does not exist
        on the table, or if the table does not exist, the default is returned instead.

        This is a convenient static wrapper for the LookupTablesCore systems. Instead of having to
        do this:

            LookupTables.get_instance().table('table_name').get('key')

        You can do this:

            LookupTables.get('table_name', 'key')


        Params:
            table_name (str)
            key (str)
            default (mixed)

        Returns:
            mixed
        """
        return cls.get_instance().get(table_name, key, default)


class LookupTablesCore:
    """
    The core component that manages LookupTables.

    This is designed to be a drop-in replacement for the original LookupTables class.
    """
    def __init__(self, config):
        self._configuration = LookupTablesConfiguration(config=config)
        self._tables = {}  # type: Dict[str, LookupTable]
        self._null_table = LookupTable('null_table', NullDriver(self._configuration), {})

    def setup_tables(self):
        """
        After setup_tables are called, the tables are constructed and ready to use.

        HOWEVER, their internal drivers are not initialized until the tables are actually used.
        This delays the step where drivers initialize connections until right before they are used,
        preventing unnecessary memory usage.
        """
        if not self._configuration.is_enabled:
            LOGGER.debug('Skipping LookupTables as it is not enabled')
            return

        for table_name, table_configuration in self._configuration.table_configurations.items():
            driver = construct_persistence_driver(table_configuration)
            self._tables[table_name] = LookupTable(table_name, driver, table_configuration)

        LOGGER.info('LookupTablesCore initialized!')

    def table(self, table_name):
        """
        Drop-in replacement method for table(), on the original LookupTables implementation, with
        a small caveat; the original implementation returns a dict, whereas this one returns an
        individual LookupTable instance.

        Params:
            table_name (str)

        Returns:
            LookupTable
        """
        return self.get_table(table_name)

    def get_table(self, table_name):
        """
        Retrieves the instance of the LookupTable requested. If the requested table name is not
        found, it will Log an error, and subsequently return a NullTable.

        Params:
            table_name (str): The name of the lookup table desired

        Returns:
            LookupTable: An individual instance. Not to be mixed up with LookupTables (plural!)
        """
        if table_name in self._tables:
            return self._tables[table_name]

        LOGGER.error(
            'Nonexistent LookupTable \'%s\' referenced. Defaulting to null table. '
            'Valid tables were (%s)', table_name, ', '.join(sorted(self._tables.keys())))

        return self._null_table

    def get(self, table_name, key, default=None):
        """
        Syntax sugar for get_table().get()

        Params:
            table_name (str)
            key (str)
            default (mixed)

        Returns:
            mixed
        """
        return self.get_table(table_name).get(key, default)

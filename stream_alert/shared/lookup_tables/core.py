from typing import Dict

from stream_alert.shared.config import load_config
from stream_alert.shared.logger import get_logger
from stream_alert.shared.lookup_tables.configuration import LookupTablesConfiguration
from stream_alert.shared.lookup_tables.drivers import (
    construct_persistence_driver,
    NullDriver,
)
from stream_alert.shared.lookup_tables.table import LookupTable

LOGGER = get_logger(__name__)


class LookupTablesCore(object):
    """
    The core component that manages LookupTables. Designed to be a drop-in replacement for
    the original LookupTables class.
    """
    _tables = None  # type: Dict[str, LookupTable]
    _null_table = None  # type: LookupTable

    def __init__(self, config=None):
        if config is None:
            config = load_config()

        self._configuration = LookupTablesConfiguration(config=config)
        self._tables = {}
        self._null_table = LookupTable('null_table', NullDriver(self._configuration), {})

    @staticmethod
    def load_lookup_tables(config):
        """Drop-in replacement method for load_lookup_tables()"""
        core = LookupTablesCore(config=config)
        core.setup_tables()

        return core

    def setup_tables(self):
        """
        After setup_tables are called, the tables are constructed but their internal drivers
        are not initialized until the tables are actually used.
        """
        if not self._configuration.is_enabled:
            LOGGER.error(
                'Cannot setup LookupTables as it has not been enabled in configuration. '
                'Have you taken a look at conf/lookup_tables.json?'
            )
            return

        for table_name, table_configuration in self._configuration.table_configurations.iteritems():
            driver = construct_persistence_driver(table_configuration)
            self._tables[table_name] = LookupTable(
                table_name,
                driver,
                table_configuration
            )

    def table(self, table_name):
        """Drop-in replacement method for table(), on the original LookupTables implementation"""
        return self.get_table(table_name)

    def get_table(self, table_name):
        """
        Retrieves the instance of the LookupTable requested. If the requested table name is not
        found, it will Log an error, and subsequently return a NullTable.

        Params:
            table_name (str): The name of the lookup table desired

        Returns:
            LookupTable
        """
        if table_name in self._tables:
            return self._tables[table_name]

        LOGGER.error(
            (
                'Nonexistent LookupTable \'%s\' referenced. Defaulting to null table. '
                'Valid tables were (%s)'
            ),
            table_name,
            ', '.join(self._tables.keys())
        )
        # FIXME (derek.wang) Would it be preferable to raise an exception instead?
        #  In the current implementation if it returns a NullTable, the code could continue
        #  executing with None values everywhere, which may cause undesirable behavior. Maybe
        #  fail fast?
        return self._null_table

        # raise LookupTablesError('Nonexistent LookupTable {} referenced.'.format(table_name))

    def get(self, table_name, key, default=None):
        """
        Syntax sugar for get_table()

        Params:
            table_name (str)
            key (str)
            default (mixed)

        Returns:
            mixed
        """
        return self.get_table(table_name).get(key, default)

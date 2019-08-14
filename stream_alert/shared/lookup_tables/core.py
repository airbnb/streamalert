from typing import Dict, Any

from stream_alert.shared.config import load_config
from stream_alert.shared.logger import get_logger
from stream_alert.shared.lookup_tables.configuration import LookupTablesConfiguration
from stream_alert.shared.lookup_tables.drivers import (
    construct_persistence_driver,
    DynamoDBDriver,
    NullDriver,
    PersistenceDriver,
    S3Driver,
)
from stream_alert.shared.lookup_tables.errors import LookupTablesConfigurationError
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
        for table_name, table_configuration in self._configuration.table_configurations.iteritems():
            driver = construct_persistence_driver(table_configuration)
            self._tables[table_name] = LookupTable(
                table_name,
                driver,
                table_configuration
            )

    def table(self, table_name):
        """Drop-in replacement method for table()"""
        return self.get_table(table_name)

    def get_table(self, table_name):
        # FIXME (derek.wang) error warning?
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
        return self._null_table

    def get(self, table_name, key, default=None):
        return self.get_table(table_name).get(key, default)

from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


class LookupTable:
    """
    A single LookupTable instance.

    LookupTables offer a standardized interface, backed by the PersistenceDriver system in
    the background.
    """
    def __init__(self, table_name, driver, table_configuration):
        self._table_name = table_name
        self._table_configuration = table_configuration
        self._driver = driver  # type: PersistenceDriver
        self._initialized = False

    @property
    def table_name(self):
        return self._table_name

    @property
    def driver_id(self):
        return self._driver.id

    @property
    def driver_type(self):
        return self._driver.driver_type

    def get(self, key, default=None):
        """
        Retrieves the value of a key in the current LookupTable

        Args:
            key (str)
            default (mixed)

        Returns:
            mixed
        """
        self._initialize_if_necessary()
        return self._driver.get(key, default)

    def _initialize_if_necessary(self):
        """
        Initializes the LookupTable's underlying driver, if it has not yet been initialized.
        """
        if self._initialized:
            return

        self._initialized = True
        self._driver.initialize()

from abc import abstractmethod, ABCMeta
from stream_alert.shared.logger import get_logger
from stream_alert.shared.lookup_tables.errors import LookupTablesConfigurationError

LOGGER = get_logger(__name__)


# pylint: disable=invalid-name
class PersistenceDriver(object):

    TYPE_S3 = 's3'
    TYPE_DYNAMODB = 'dynamodb'
    TYPE_NULL = 'null'
    TYPE_EPHEMERAL = 'ephemeral'

    __metaclass__ = ABCMeta

    def __init__(self, configuration):
        self._configuration = configuration

    @property
    @abstractmethod
    def driver_type(self):
        """Returns a string that describes the type of driver"""

    @property
    @abstractmethod
    def id(self):
        """Returns a unique id for this driver"""

    @abstractmethod
    def initialize(self):
        """
        Configures and initializes this driver

        Initialization is called exactly once, and is should always called BEFORE any other
        interaction (get/set/commit) is made with the driver.
        """

    @abstractmethod
    def commit(self):
        """
        Takes any changes and flushes them to remote storage.
        """

    @abstractmethod
    def get(self, key, default=None):
        """Retrieves a key"""

    @abstractmethod
    def set(self, key, value):
        """
        Modifies the value of a key in the LookupTable.

        For LookupTables with remote persistence, you will need to call commit() in order to
        permanently persist the changes.
        """


def construct_persistence_driver(table_configuration):
    """
    Constructs a raw, uninitialized PersistenceDriver from the given configuration.

    :args
        table_configuration (dict)

    :return
        PersistenceDriver
    """
    import stream_alert.shared.lookup_tables.driver_dynamodb as driver_dynamodb
    import stream_alert.shared.lookup_tables.driver_s3 as driver_s3

    driver_name = table_configuration.get('driver', False)

    if driver_name == PersistenceDriver.TYPE_S3:
        return driver_s3.S3Driver(table_configuration)
    elif driver_name == PersistenceDriver.TYPE_DYNAMODB:
        return driver_dynamodb.DynamoDBDriver(table_configuration)
    elif driver_name == PersistenceDriver.TYPE_NULL:
        return NullDriver(table_configuration)
    elif driver_name == PersistenceDriver.TYPE_EPHEMERAL:
        return EphemeralDriver(table_configuration)
    else:
        raise LookupTablesConfigurationError(
            'Unrecognized driver name: {}'.format(driver_name)
        )


class EphemeralDriver(PersistenceDriver):
    """
    Ephemeral persistence driver

    This persistence driver does not actually store data anywhere--it just keeps it in memory.
    """

    def __init__(self, configuration):
        super(EphemeralDriver, self).__init__(configuration)
        self._cache = {}

    def initialize(self):
        pass

    def commit(self):
        pass

    @property
    def driver_type(self):
        return self.TYPE_EPHEMERAL

    @property
    def id(self):
        return '{}:{}'.format(self.driver_type, 1)

    def get(self, key, default=None):
        return self._cache.get(key, default)

    def set(self, key, value):
        self._cache[key] = value


class NullDriver(PersistenceDriver):
    """
    This driver does nothing... goes nowhere. It's simply to prevent our system from crashing
    if a nonexistent LookupTable is referenced--in this case, we simply return the Null table,
    backed by this NullDriver.
    """

    @property
    def driver_type(self):
        return self.TYPE_NULL

    @property
    def id(self):
        return '{}:{}'.format(self.driver_type, 1)

    def initialize(self):
        pass

    def commit(self):
        pass

    def get(self, _, default=None):
        return default

    def set(self, _, __):
        pass

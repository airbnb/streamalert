from streamalert.shared.lookup_tables.drivers import (EphemeralDriver,
                                                      NullDriver,
                                                      PersistenceDriver)
from streamalert.shared.lookup_tables.errors import \
    LookupTablesConfigurationError


def construct_persistence_driver(table_configuration):
    """
    Constructs a raw, uninitialized PersistenceDriver from the given configuration.

    Params:
        table_configuration (dict)

    Returns:
        PersistenceDriver
    """
    # pylint: disable=import-outside-toplevel
    from streamalert.shared.lookup_tables import driver_dynamodb
    from streamalert.shared.lookup_tables import driver_s3
    # pylint: enable=import-outside-toplevel

    driver_name = table_configuration.get('driver', False)

    if driver_name == PersistenceDriver.TYPE_S3:
        return driver_s3.S3Driver(table_configuration)

    if driver_name == PersistenceDriver.TYPE_DYNAMODB:
        return driver_dynamodb.DynamoDBDriver(table_configuration)

    if driver_name == PersistenceDriver.TYPE_NULL:
        return NullDriver(table_configuration)

    if driver_name == PersistenceDriver.TYPE_EPHEMERAL:
        return EphemeralDriver(table_configuration)

    raise LookupTablesConfigurationError(f'Unrecognized driver name: {driver_name}')

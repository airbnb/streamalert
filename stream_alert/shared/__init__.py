"""Define some shared resources."""
import logging
import os


ALERT_PROCESSOR_NAME = 'alert_processor'
ATHENA_PARTITION_REFRESH_NAME = 'athena_partition_refresh'
RULE_PROCESSOR_NAME = 'rule_processor'

# Create a package level logger to import
LEVEL = os.environ.get('LOGGER_LEVEL', 'INFO').upper()

# Cast integer levels to avoid a ValueError
if LEVEL.isdigit():
    LEVEL = int(LEVEL)

logging.basicConfig()
LOGGER = logging.getLogger('StreamAlertShared')
try:
    LOGGER.setLevel(LEVEL)
except (TypeError, ValueError) as err:
    LOGGER.setLevel('INFO')
    LOGGER.error('Defaulting to INFO logging: %s', err)

"""Initialize logging for the alert processor."""
import logging
import os

from stream_alert.shared import ALERT_PROCESSOR_NAME as FUNCTION_NAME

# Create a package level logger to import
LEVEL = os.environ.get('LOGGER_LEVEL', 'INFO').upper()

# Cast integer levels to avoid a ValueError
if LEVEL.isdigit():
    LEVEL = int(LEVEL)

logging.basicConfig(format='%(name)s [%(levelname)s]: [%(module)s.%(funcName)s] %(message)s')

LOGGER = logging.getLogger('StreamAlertOutput')
try:
    LOGGER.setLevel(LEVEL)
except (TypeError, ValueError) as err:
    LOGGER.setLevel('INFO')
    LOGGER.error('Defaulting to INFO logging: %s', err)

import logging
import os

# Create a package level logger to import
LEVEL = os.environ.get('LOGGER_LEVEL', 'INFO')
logging.basicConfig()
LOGGER = logging.getLogger('StreamAlert')
LOGGER.setLevel(LEVEL.upper())

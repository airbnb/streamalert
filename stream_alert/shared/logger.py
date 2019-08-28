"""
Copyright 2017-present, Airbnb Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import logging
import os


def get_logger(name, level=None):
    """Get a logger instance for the specified name.

    Args:
        name (str): Name for logger object being created
        level (str='INFO'): Initial log level for logger object being created

    Returns:
        logging.Logger: Instance of logging.Logger with the specified name

    """
    if not level:
        level = os.environ.get('LOGGER_LEVEL', 'INFO')

    logging.basicConfig(format='[%(levelname)s %(asctime)s (%(name)s:%(lineno)d)]: %(message)s')
    logger = logging.getLogger(name)

    try:
        logger.setLevel(level.upper())
    except (TypeError, ValueError) as err:
        logger.setLevel('INFO')
        logger.error('Defaulting to INFO logging: %s', str(err))

    return logger

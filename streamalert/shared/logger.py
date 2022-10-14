"""
Copyright 2017-present Airbnb, Inc.

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

LOCAL_LOGGER_FMT = '[%(levelname)s %(asctime)s (%(name)s:%(lineno)d)]: %(message)s'

logging.basicConfig(level=logging.INFO, format=LOCAL_LOGGER_FMT)


class LogFormatter(logging.Formatter):
    def formatException(self, ei):
        """Override the default exception logger so it looks nice in CloudWatch Logs"""
        value = super().formatException(ei)

        # Replace the newlines with carriage returns
        return value.replace('\n', '\r')


def set_formatter(logger):
    """
    The Lambda execution environment injects a default `LambdaLoggerHandler`
    into the root logger, so we just want to update the traceback formatter on
    it without changing the actual logging format.

    Alternatively, locally the root logger will not have any handlers. In this case,
    we create a logging.StreamHandler and add the formatter to it.

    Args:
        logger (logging.Logger): An instance of a logger for which to update the formatter
    """
    # Update the LambdaLoggerHandler formatter if there is one
    if not logger.hasHandlers():
        return

    for handler in logger.handlers + logger.parent.handlers:
        # pylint: disable=protected-access
        # Retain the handlers format spec if it has one
        fmt = handler.formatter._fmt if handler.formatter else None
        handler.setFormatter(LogFormatter(fmt=fmt))


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

    logger = logging.getLogger(name)

    set_formatter(logger)

    try:
        logger.setLevel(level.upper())
    except (TypeError, ValueError) as err:
        logger.setLevel('INFO')
        logger.error('Defaulting to INFO logging: %s', str(err))

    return logger

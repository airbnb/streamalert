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
from unittest.mock import patch

from streamalert.shared.logger import LogFormatter, get_logger, set_formatter


def test_get_logger():
    """Shared - Get Logger, Defaults"""
    logger_name = 'unittest'
    logger = get_logger(logger_name)
    assert logger.name == logger_name
    assert logging.getLevelName(logger.getEffectiveLevel()) == 'INFO'


def test_get_logger_env_level():
    """Shared - Get Logger, Environment Level"""
    level = 'DEBUG'
    with patch.dict(os.environ, {'LOGGER_LEVEL': level}):
        logger = get_logger('test')

    assert logging.getLevelName(logger.getEffectiveLevel()) == level


def test_get_logger_user_level():
    """Shared - Get Logger, User Defined Level"""
    level = 'CRITICAL'
    logger = get_logger('test', level)
    assert logging.getLevelName(logger.getEffectiveLevel()) == level


@patch('logging.Logger.error')
def test_get_logger_bad_level(log_mock):
    """Shared - Get Logger, Bad Level"""
    logger = get_logger('test', 'foo')
    assert logging.getLevelName(logger.getEffectiveLevel()) == 'INFO'
    log_mock.assert_called_with('Defaulting to INFO logging: %s', 'Unknown level: \'FOO\'')


def test_set_logger_formatter_existing_handler():
    """Shared - Set Logger Formatter, Existing Handler"""
    logger = logging.getLogger('test')  # non-root logger

    # Create handler to be added
    # This simulates what happens in the Lambda execution environment
    handler = logging.StreamHandler()
    logger.addHandler(handler)

    # Now set the formatter on the logger that already has a handler
    set_formatter(logger)

    assert isinstance(handler.formatter, LogFormatter)


@patch('logging.Logger.hasHandlers')
def test_set_logger_formatter_new_handler(log_mock):
    """Shared - Set Logger Formatter, New Handler"""
    logger = logging.getLogger('test')  # non-root logger

    # Hack because nosetests uses a `MyMemoryHandler` that is attached to loggers
    log_mock.return_value = False

    # Set the formatter on the logger that does not have any existing handlers
    set_formatter(logger)

    assert isinstance(logger.handlers[0].formatter, LogFormatter)

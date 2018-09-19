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

from mock import patch
from nose.tools import assert_equal

from stream_alert.shared.logger import get_logger


def test_get_logger():
    """Shared - Get Logger, Defaults"""
    logger_name = 'unittest'
    logger = get_logger(logger_name)
    assert_equal(logger.name, logger_name)
    assert_equal(logging.getLevelName(logger.getEffectiveLevel()), 'INFO')


def test_get_logger_env_level():
    """Shared - Get Logger, Environment Level"""
    level = 'DEBUG'
    with patch.dict(os.environ, {'LOGGER_LEVEL': level}):
        logger = get_logger('test')

    assert_equal(logging.getLevelName(logger.getEffectiveLevel()), level)


def test_get_logger_user_level():
    """Shared - Get Logger, User Defined Level"""
    level = 'CRITICAL'
    logger = get_logger('test', level)
    assert_equal(logging.getLevelName(logger.getEffectiveLevel()), level)


@patch('logging.Logger.error')
def test_get_logger_bad_level(log_mock):
    """Shared - Get Logger, Bad Level"""
    logger = get_logger('test', 'foo')
    assert_equal(logging.getLevelName(logger.getEffectiveLevel()), 'INFO')
    log_mock.assert_called_with('Defaulting to INFO logging: %s', 'Unknown level: \'FOO\'')

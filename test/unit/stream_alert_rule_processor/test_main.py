'''
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
'''
import os

from mock import call, patch

from nose.tools import assert_equal

import stream_alert.rule_processor as rp

from unit.stream_alert_rule_processor.test_helpers import _get_mock_context


@patch('stream_alert.rule_processor.main.StreamAlert.run')
def test_handler(mock_runner):
    """Rule Processor Main - Test Handler"""

    rp.main.handler('event', _get_mock_context())

    mock_runner.assert_called_with('event')


@patch('stream_alert.rule_processor.LOGGER.error')
def test_init_logging_bad(log_mock):
    """Rule Processor Init - Logging, Bad Level"""
    level = 'IFNO'

    os.environ['LOGGER_LEVEL'] = level

    # Force reload the rule_processor package to trigger the init
    reload(rp)

    message = str(call('Defaulting to INFO logging: %s',
                       ValueError("Unknown level: 'IFNO'",)))

    assert_equal(str(log_mock.call_args_list[0]), message)


@patch('stream_alert.rule_processor.LOGGER.setLevel')
def test_init_logging_int_level(log_mock):
    """Rule Processor Init - Logging, Integer Level"""
    level = '10'

    os.environ['LOGGER_LEVEL'] = level

    # Force reload the rule_processor package to trigger the init
    reload(rp)

    log_mock.assert_called_with(10)

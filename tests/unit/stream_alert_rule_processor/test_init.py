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
import os

from mock import call, patch
from nose.tools import assert_equal

import stream_alert.rule_processor as rp


@patch('stream_alert.rule_processor.LOGGER.error')
@patch.dict(os.environ, {'LOGGER_LEVEL': 'INVALID'})
def test_init_logging_bad(log_mock):
    """Rule Processor Init - Logging, Bad Level"""
    # Force reload the rule_processor package to trigger the init
    reload(rp)

    message = str(call('Defaulting to INFO logging: %s',
                       ValueError('Unknown level: \'INVALID\'',)))

    assert_equal(str(log_mock.call_args_list[0]), message)


@patch('stream_alert.rule_processor.LOGGER.setLevel')
@patch.dict(os.environ, {'LOGGER_LEVEL': '10'})
def test_init_logging_int_level(log_mock):
    """Rule Processor Init - Logging, Integer Level"""
    # Force reload the rule_processor package to trigger the init
    reload(rp)

    log_mock.assert_called_with(10)

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
import json

from collections import OrderedDict
from mock import patch, call

from nose.tools import assert_equal

from stream_alert.alert_processor.main import (
    _load_output_config,
    _sort_dict,
    handler
)

from unit.stream_alert_alert_processor import (
    REGION,
    FUNCTION_NAME
)

from unit.stream_alert_alert_processor.helpers import _get_mock_context


@patch('logging.Logger.error')
def test_handler_malformed_message(log_mock):
    """Main handler decode failure logging"""
    # The @patch() decorator allows us to 'introspect' what occurs down the chain
    # and verify the params a function was LAST called with. For instance, here
    # we are checking the last call to `logging.Logger.error` and verifying that the
    # function was called with two params, the first being 'Malformed SNS: %s' and
    # the second being the dictionary contained within `message`
    # This call should happen at stream_alert/alert_processor/main.py:62
    context = _get_mock_context()
    message = {'not_default': {'record': {'size': '9982'}}}
    event = {'Records': [{'Sns': {'Message': json.dumps(message)}}]}
    handler(event, context)
    log_mock.assert_called_with('Malformed SNS: %s', message)


@patch('logging.Logger.error')
def test_handler_bad_message(log_mock):
    """Main handler decode failure logging"""
    context = _get_mock_context()
    event = {'Records': [{'Sns': {'Message': 'this\nvalue\nshould\nfail\nto\ndecode'}}]}
    handler(event, context)
    assert_equal(str(log_mock.call_args_list[0]),
                 str(call('An error occurred while decoding message to JSON: %s',
                          ValueError('No JSON object could be decoded',))))


@patch('stream_alert.alert_processor.main.run')
def test_handler_run(run_mock):
    """Main handler `run` call params"""
    context = _get_mock_context()
    message = {'default': {'record': {'size': '9982'}}}
    event = {'Records': [{'Sns': {'Message': json.dumps(message)}}]}
    handler(event, context)

    # This test will load the actual config, so we should compare the
    # function call against the same config here.
    run_mock.assert_called_with(message, REGION, FUNCTION_NAME, _load_output_config())


def test_load_output_config():
    """Load outputs configuration file"""
    config = _load_output_config('test/unit/conf/outputs.json')

    assert_equal(set(config.keys()), {
        'aws-s3', 'aws-lambda', 'pagerduty', 'phantom', 'slack'})


def test_sort_dict():
    """Sorted Dict"""
    dict_to_sort = {'c': 100, 'd': 1000, 'a': 1, 'b': 10, 'e': 100, 'f': 10, 'g': 1}
    sorted_dict = _sort_dict(dict_to_sort)

    assert_equal(type(sorted_dict), OrderedDict)

    index = 0
    keys = ['a', 'b', 'c', 'd', 'e', 'f', 'g']
    for key in sorted_dict.keys():
        assert_equal(keys[index], key)
        index += 1

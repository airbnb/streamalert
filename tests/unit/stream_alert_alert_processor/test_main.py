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
# pylint: disable=protected-access
from collections import OrderedDict
import json
import os

from mock import call, mock_open, patch
from nose.tools import (
    assert_equal,
    assert_is_instance,
    assert_list_equal,
    assert_true,
    with_setup
)

import stream_alert.alert_processor as ap
from stream_alert.alert_processor.main import _load_output_config, _sort_dict, handler
from tests.unit.stream_alert_alert_processor import FUNCTION_NAME, REGION
from tests.unit.stream_alert_alert_processor.helpers import get_alert, get_mock_context


@patch('stream_alert.alert_processor.main.run')
def test_handler_run(run_mock):
    """Main handler `run` call params"""
    context = get_mock_context()
    handler(None, context)

    # This test will load the actual config, so we should compare the
    # function call against the same config here.
    run_mock.assert_called_with(None, REGION, FUNCTION_NAME, _load_output_config())


@patch('logging.Logger.error')
def test_bad_config(log_mock):
    """Load output config - bad config"""
    mock = mock_open(read_data='non-json string that will log an error')
    with patch('__builtin__.open', mock):
        handler(None, None)

    log_mock.assert_called_with(
        'The \'%s\' file could not be loaded into json',
        'conf/outputs.json')


def test_handler_return():
    """Main handler return value"""
    context = get_mock_context()
    event = {'Records': []}
    value = handler(event, context)

    assert_is_instance(value, list)


def test_load_output_config():
    """Load outputs configuration file"""
    config = _load_output_config('tests/unit/conf/outputs.json')

    assert_equal(set(config.keys()), {
        'aws-s3', 'aws-lambda', 'pagerduty', 'phantom', 'slack'})


def test_sort_dict():
    """Sorted Dict"""
    dict_to_sort = {'c': 100, 'd': 1000, 'a': 1, 'b': 10, 'e': 100, 'f': 10, 'g': 1}
    sorted_dict = _sort_dict(dict_to_sort)

    assert_equal(type(sorted_dict), OrderedDict)

    keys = ['a', 'b', 'c', 'd', 'e', 'f', 'g']
    for index, key in enumerate(sorted_dict.keys()):
        assert_equal(keys[index], key)


def test_sort_dict_recursive():
    """Sorted Dict Recursion"""
    dict_to_sort = {'c': 100, 'a': 1, 'b': {'b': 10, 'c': 1000, 'a': 1}}
    sorted_dict = _sort_dict(dict_to_sort)

    assert_equal(type(sorted_dict), OrderedDict)
    assert_equal(type(sorted_dict['b']), OrderedDict)

    sub_keys = ['a', 'b', 'c']
    for index, key in enumerate(sorted_dict['b'].keys()):
        assert_equal(sub_keys[index], key)


@patch('urllib2.urlopen')
@patch('stream_alert.alert_processor.main._load_output_config')
@patch('stream_alert.alert_processor.output_base.StreamOutputBase._load_creds')
def test_running_success(creds_mock, config_mock, url_mock):
    """Alert Processor run handler - success"""
    config_mock.return_value = _load_output_config('tests/unit/conf/outputs.json')
    creds_mock.return_value = {'url': 'mock.url'}
    url_mock.return_value.getcode.return_value = 200

    alert = get_alert()
    context = get_mock_context()

    result = handler(alert, context)
    assert_is_instance(result, list)

    assert_true(result[0][0])


@patch('logging.Logger.error')
@patch('stream_alert.alert_processor.main._load_output_config')
def test_running_bad_output(config_mock, log_mock):
    """Alert Processor run handler - bad output"""
    config_mock.return_value = _load_output_config('tests/unit/conf/outputs.json')

    alert = get_alert()
    alert['outputs'] = ['slack']
    context = get_mock_context()

    handler(alert, context)

    log_mock.assert_called_with(
        'Improperly formatted output [%s]. Outputs for rules must '
        'be declared with both a service and a descriptor for the '
        'integration (ie: \'slack:my_channel\')', 'slack')

    alert['outputs'] = ['slakc:test']

    handler(alert, context)

    log_mock.assert_called_with(
        'The output \'%s\' does not exist!', 'slakc:test')


@patch('stream_alert.alert_processor.main._load_output_config')
@patch('stream_alert.alert_processor.main.get_output_dispatcher')
def test_running_no_dispatcher(dispatch_mock, config_mock):
    """Alert Processor run handler - no dispatcher"""
    config_mock.return_value = _load_output_config('tests/unit/conf/outputs.json')
    dispatch_mock.return_value = None

    alert = get_alert()
    context = get_mock_context()

    result = handler(alert, context)

    assert_is_instance(result, list)
    assert_list_equal(result, [])


@patch('logging.Logger.exception')
@patch('urllib2.urlopen')
@patch('stream_alert.alert_processor.main._load_output_config')
@patch('stream_alert.alert_processor.main.get_output_dispatcher')
@patch('stream_alert.alert_processor.output_base.StreamOutputBase._load_creds')
def test_running_exception_occurred(creds_mock, dispatch_mock, config_mock, url_mock, log_mock):
    """Alert Processor run handler - exception occurred"""
    # Use TypeError as the mock's side_effect
    err = TypeError('bad error')
    creds_mock.return_value = {'url': 'mock.url'}
    dispatch_mock.return_value.dispatch.side_effect = err
    config_mock.return_value = _load_output_config('tests/unit/conf/outputs.json')
    url_mock.return_value.getcode.return_value = 200

    alert = _sort_dict(get_alert())
    context = get_mock_context()

    handler(alert, context)

    log_mock.assert_called_with(
        'An error occurred while sending alert '
        'to %s:%s: %s. alert:\n%s', 'slack', 'unit_test_channel',
        err, json.dumps(alert, indent=2))

def _teardown_env():
    """Helper method to reset environment variables"""
    if 'LOGGER_LEVEL' in os.environ:
        del os.environ['LOGGER_LEVEL']


@with_setup(setup=None, teardown=_teardown_env)
@patch('stream_alert.alert_processor.LOGGER.error')
def test_init_logging_bad(log_mock):
    """Alert Processor Init - Logging, Bad Level"""
    level = 'IFNO'

    os.environ['LOGGER_LEVEL'] = level

    # Force reload the alert_processor package to trigger the init
    reload(ap)

    message = str(call('Defaulting to INFO logging: %s',
                       ValueError('Unknown level: \'IFNO\'',)))

    assert_equal(str(log_mock.call_args_list[0]), message)


@with_setup(setup=None, teardown=_teardown_env)
@patch('stream_alert.alert_processor.LOGGER.setLevel')
def test_init_logging_int_level(log_mock):
    """Alert Processor Init - Logging, Integer Level"""
    level = '10'

    os.environ['LOGGER_LEVEL'] = level

    # Force reload the alert_processor package to trigger the init
    reload(ap)

    log_mock.assert_called_with(10)

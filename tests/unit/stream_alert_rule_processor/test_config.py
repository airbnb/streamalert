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
# command: nosetests -v -s tests/unit/
# specific test: nosetests -v -s tests/unit/file.py:TestStreamPayload.test_name

# pylint: disable=protected-access
from mock import mock_open, patch
from nose.tools import assert_equal, raises, nottest

from stream_alert.rule_processor.config import (
    _validate_config,
    ConfigError,
    load_config,
    load_env
)

from tests.unit.stream_alert_rule_processor.test_helpers import get_mock_context, get_valid_config


@raises(ConfigError)
def test_load_config_invalid():
    """Config Validator - Load Config - Invalid"""
    mocker = mock_open(read_data='test string that will throw an error')
    with patch('__builtin__.open', mocker):
        load_config()


@raises(ConfigError)
def test_config_no_schema():
    """Config Validator - No Schema in Log"""
    # Load a valid config
    config = get_valid_config()

    # Remove the 'schema' keys from the config
    config['logs']['json_log'].pop('schema')
    config['logs']['csv_log'].pop('schema')

    _validate_config(config)


@raises(ConfigError)
def test_config_no_parsers():
    """Config Validator - No Parser in Log"""
    # Load a valid config
    config = get_valid_config()

    # Remove the 'parser' keys from the config
    config['logs']['json_log'].pop('parser')
    config['logs']['csv_log'].pop('parser')

    _validate_config(config)


@raises(ConfigError)
def test_config_no_logs_key():
    """Config Validator - No Logs Key in Source"""
    # Load a valid config
    config = get_valid_config()

    # Remove everything from the sources entry
    config['sources']['kinesis']['stream_1'] = {}

    _validate_config(config)


@raises(ConfigError)
def test_config_empty_logs_list():
    """Config Validator - Empty Logs List in Source"""
    # Load a valid config
    config = get_valid_config()

    # Set the logs key to an empty list
    config['sources']['kinesis']['stream_1']['logs'] = []

    _validate_config(config)


@raises(ConfigError)
def test_config_invalid_datasources():
    """Config Validator - Invalid Datasources"""
    # Load a valid config
    config = get_valid_config()

    # Set the sources value to contain an invalid data source ('sqs')
    config['sources'] = {'sqs': {'queue_1': {}}}

    _validate_config(config)


def test_load_env():
    """Config - Environment Loader"""
    context = get_mock_context()

    env = load_env(context)
    assert_equal(env['lambda_region'], 'us-east-1')
    assert_equal(env['account_id'], '123456789012')
    assert_equal(env['lambda_function_name'],
                 'corp-prefix_prod_streamalert_rule_processor')
    assert_equal(env['lambda_alias'], 'development')


@nottest
#TODO(chunyong) add assertions to this test
def test_config_valid_types():
    """Config Validator - valid normalized types"""
    # Load a valid config
    config = load_config()

    _validate_config(config)

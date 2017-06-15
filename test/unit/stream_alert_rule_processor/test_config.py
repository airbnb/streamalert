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

# command: nosetests -v -s test/unit/
# specific test: nosetests -v -s test/unit/file.py:TestStreamPayload.test_name

from collections import namedtuple

from nose.tools import assert_equal, raises

from stream_alert.rule_processor.config import (
    ConfigError,
    validate_config,
    load_env
)

def test_validate_config_valid():
    """Config Validator - Valid Config"""
    config = {
        'logs': {
            'json_log': {
                'schema': {
                    'name': 'string'
                },
                'parser': 'json'
            },
            'csv_log': {
                'schema': {
                    'data': 'string',
                    'uid': 'integer'
                },
                'parser': 'csv'
            }
        },
        'sources': {
            'kinesis': {
                'stream_1': {
                    'logs': [
                        'json_log',
                        'csv_log'
                    ]
                }
            }
        }
    }

    validate_result = validate_config(config)
    assert_equal(validate_result, True)

@raises(ConfigError)
def test_validate_config_no_parsers():
    """Config Validator - No Parsers"""
    config = {
        'logs': {
            'json_log': {
                'schema': {
                    'name': 'string'
                }
            },
            'csv_log': {
                'schema': {
                    'data': 'string',
                    'uid': 'integer'
                }
            }
        },
        'sources': {
            'kinesis': {
                'stream_1': {
                    'logs': [
                        'json_log',
                        'csv_log'
                    ]
                }
            }
        }
    }

    validate_config(config)

@raises(ConfigError)
def test_validate_config_no_logs():
    """Config Validator - No Logs"""
    config = {
        'logs': {
            'json_log': {
                'schema': {
                    'name': 'string'
                }
            },
            'csv_log': {
                'schema': {
                    'data': 'string',
                    'uid': 'integer'
                }
            }
        },
        'sources': {
            'kinesis': {
                'stream_1': {}
            }
        }
    }

    validate_config(config)

def test_load_env():
    """Config Environment Validator"""
    context = namedtuple('Context', ['invoked_function_arn'])
    context.invoked_function_arn = ('arn:aws:lambda:us-east-1:555555555555:'
                                    'function:streamalert_testing:production')

    env = load_env(context)
    assert_equal(env['lambda_region'], 'us-east-1')
    assert_equal(env['account_id'], '555555555555')
    assert_equal(env['lambda_function_name'], 'streamalert_testing')
    assert_equal(env['lambda_alias'], 'production')

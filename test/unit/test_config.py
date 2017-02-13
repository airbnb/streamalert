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

import base64
import json

from collections import OrderedDict

from nose.tools import (
    assert_equal,
    assert_not_equal,
    nottest,
    assert_raises,
    raises
)

from stream_alert.config import (
    ConfigError,
    load_config,
    validate_config
)

def test_validate_config_valid():
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

    validate_result = validate_config(config)

@raises(ConfigError)
def test_validate_config_no_logs():
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

    validate_result = validate_config(config)
    
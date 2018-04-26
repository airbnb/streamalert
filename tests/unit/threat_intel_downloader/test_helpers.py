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
from copy import deepcopy

from mock import Mock

from tests.unit.threat_intel_downloader import CONFIG, FUNCTION_NAME, REGION

def mock_config():
    """Return a copy of the config with the env set"""
    ti_config = deepcopy(CONFIG['lambda']['threat_intel_downloader_config'])
    ti_config.update({
        'account_id': '123456789012',
        'function_name': 'prefix_threat_intel_downloader',
        'qualifier': 'development',
        'region': 'us-east-1',
    })
    return ti_config


def get_mock_context():
    """Helper function to create a fake context object using Mock"""
    arn = 'arn:aws:lambda:{}:123456789012:function:{}:development'
    context = Mock(invoked_function_arn=(arn.format(REGION, FUNCTION_NAME)),
                   function_name=FUNCTION_NAME,
                   get_remaining_time_in_millis=Mock(return_value=100))

    return context


class MockRequestsResponse(object): # pylint: disable=too-few-public-methods
    """Mocking class to mock requests.get() call"""
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        """Return data in json format"""
        return self.json_data


def mock_requests_get(*args, **kwargs): # pylint: disable=unused-argument
    """Method to mock requests.get() call"""
    return MockRequestsResponse({
        "key1": "value1",
        "objects": [
            {
                'value': 'malicious_domain.com',
                'itype': 'c2_domain',
                'source': 'ioc_source',
                'type': 'domain',
                'expiration_ts': '2017-12-31T00:01:02.123Z',
                'key1': 'value1',
                'key2': 'value2'
            },
            {
                'value': 'malicious_domain2.com',
                'itype': 'c2_domain',
                'source': 'test_source',
                'type': 'domain',
                'expiration_ts': '2017-11-30T00:01:02.123Z',
                'key1': 'value1',
                'key2': 'value2'
            }
        ],
        "meta": {
            "next": None,
            "offset": 100
            }
        }, 200)


def mock_ssm_response():
    return {
        'threat_intel_downloader_api_creds': '{"api_user": "test_user", "api_key": "test_key"}',
        'ti_test_state': '{"next_url": "test_next_url", "continue_invoke": "False"}'
    }


def mock_invalid_ssm_response():
    return {
        'threat_intel_downloader_api_creds': 'invalid_value'
    }

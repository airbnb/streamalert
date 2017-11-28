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
from mock import Mock

from tests.unit.threat_intel_downloader import FUNCTION_NAME, REGION


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

def mock_config():
    '''Helper function to create a fake config for Threat Intel Downloader'''
    return {
        'account_id': '123456789012',
        'function_name': 'prefix_threat_intel_downloader',
        'handler': 'stream_alert.threat_intel_downloader.main.handler',
        'interval': 'rate(1 day)',
        'ioc_filters': ['crowdstrike', '@airbnb.com'],
        'ioc_keys': ['expiration_ts', 'itype', 'source', 'type', 'value'],
        'ioc_types': ['domain', 'ip', 'md5'],
        'log_level': 'info',
        'memory': '128',
        'qualifier': 'development',
        'region': 'us-east-1',
        'table_rcu': 10,
        'table_wcu': 10,
        'timeout': '180'
    }

LAMBDA_FILE = 'conf/lambda.json'

LAMBDA_SETTINGS = {
    'alert_processor_config': {
        'handler': 'stream_alert.alert_processor.main.handler',
        'source_bucket': 'unit-testing.streamalert.source',
        'source_current_hash': '<auto_generated>',
        'source_object_key': '<auto_generated>',
        'third_party_libraries': []
    },
    'rule_processor_config': {
        'handler': 'stream_alert.rule_processor.main.handler',
        'source_bucket': 'unit-testing.streamalert.source',
        'source_current_hash': '<auto_generated>',
        'source_object_key': '<auto_generated>',
        'third_party_libraries': [
            'jsonpath_rw',
            'netaddr'
        ]
    },
    'threat_intel_downloader_config': {
        'enabled': True,
        'handler': 'main.handler',
        'timeout': '60',
        'memory': '128',
        'source_bucket': 'unit-testing.streamalert.source',
        'source_current_hash': '<auto_generated>',
        'source_object_key': '<auto_generated>',
        'third_party_libraries': []
    }
}

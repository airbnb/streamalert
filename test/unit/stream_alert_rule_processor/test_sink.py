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

import random
import base64

from nose.tools import assert_equal

import stream_alert.rule_processor.sink as sink

class TestStreamSink(object):
    """Test class for StreamSink"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.env = {
            'lambda_region': 'us-east-1',
            'account_id': '123456789012',
            'lambda_function_name': 'unittest_prod_streamalert_rule_processor',
            'lambda_alias': 'production'
        }

    @classmethod
    def teardown_class(cls):
        """Teardown the class after any methods"""
        cls.env = None

    @staticmethod
    def test_json_from_dict():
        """Sink SNS Messaging - Dictionary to JSON Marshalling"""
        # Create a dictionary with an empty alert list
        alert = {"test": "alert"}
        json_message = sink._json_dump(alert)

        # Test empty dictionary
        assert_equal(json_message, '{"test": "alert"}')

        # Create a dictionary with a single alert in the list
        alert = {
            'record': {
                'record_data_key01_01': "record_data_value01_01",
                'record_data_key02_01': "record_data_value02_01"
                },
            'metadata': {
                'rule_name': "test_rule_01",
                'log': "payload_data_01",
                'outputs': "rule.outputs_01",
                'type': "payload_type_01",
                'source': {
                    'service': "payload_service_01",
                    'entity': "payload_entity_01"
                }
            }
        }

        json_message = sink._json_dump(alert)

        # Test with single alert entry
        assert_equal(json_message, '{"record": {"record_data_key02_01": ' \
            '"record_data_value02_01", "record_data_key01_01": "record_data_value01_01"}, ' \
            '"metadata": {"source": {"service": "payload_service_01", ' \
            '"entity": "payload_entity_01"}, "rule_name": "test_rule_01", ' \
            '"type": "payload_type_01", "log": "payload_data_01", ' \
            '"outputs": "rule.outputs_01"}}')

def get_payload(byte_size):
    """Returns a base64 encoded random payload of (roughly) byte_size length

    Args:
        byte_size: The number of bytes to return after base64 encoding
    """
    size_before_b64 = (byte_size / 4) * 3
    return base64.b64encode(bytearray(random.getrandbits(8) for _ in range(size_before_b64)))

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
from nose.tools import assert_true, assert_false

from stream_alert.alert_processor.helpers import (
    validate_alert
)

from unit.stream_alert_alert_processor.helpers import _get_alert

def test_valid_alert():
    """Alert Processor Input Validation - Valid Alert Structure"""
    # Default valid alert to test
    valid_alert = _get_alert()

    # Test with a valid alert structure
    assert_true(validate_alert(valid_alert))


def test_root_keys():
    """Alert Processor Input Validation - Invalid Root Keys"""
    # Default valid alert to be modified
    invalid_root_keys = _get_alert()

    # Remove 'metadata' key to break root key validation
    invalid_root_keys.pop('metadata')

    # Test with invalid root keys
    assert_false(validate_alert(invalid_root_keys))


def test_metadata_value():
    """Alert Processor Input Validation - Invalid Root Metadata Value"""
    # Default valid alert to be modified
    invalid_root_values = _get_alert()

    # Make the 'metadata' key's value a list to break root value validation
    invalid_root_values['metadata'] = ['value']

    # Test with invalid root values
    assert_false(validate_alert(invalid_root_values))


def test_metadata_keys():
    """Alert Processor Input Validation - Metadata Keys Missing"""
    # Default valid alert to be modified
    invalid_metadata_keys = _get_alert()

    # Alter 'metadata' keys to break validation (not all required keys)
    invalid_metadata_keys['metadata'] = {'log': 'osquery'}

    # Test with invalid metadata keys
    assert_false(validate_alert(invalid_metadata_keys))


def test_metadata_source_keys():
    """Alert Processor Input Validation - Source Keys Missing"""
    # Default valid alert to be modified
    invalid_metadata_source = _get_alert()

    # metadata > source key validation
    invalid_metadata_source['metadata']['source'] = {'service': 'kinesis'}

    # Test with invalid metadata source keys
    assert_false(validate_alert(invalid_metadata_source))


def test_metadata_source_value():
    """Alert Processor Input Validation - Source Entity Value"""
    # Default valid alert to be modified
    invalid_metadata_source = _get_alert()

    # metadata > source value validation
    invalid_metadata_source['metadata']['source']['entity'] = 100

    # Test with invalid metadata source values
    assert_false(validate_alert(invalid_metadata_source))


def test_outputs_type():
    """Alert Processor Input Validation - Metadata Outputs Bad Type"""
    # Default valid alert to be modified
    invalid_metadata_outputs = _get_alert()

    # metadata > outputs type validation
    invalid_metadata_outputs['metadata']['outputs'] = {'bad': 'value'}

    # Test with invalid metadata outputs type
    assert_false(validate_alert(invalid_metadata_outputs))


def test_outputs_value_type():
    """Alert Processor Input Validation - Metadata Outputs Bad Value Type"""
    # Default valid alert to be modified
    invalid_metadata_outputs = _get_alert()

    # metadata > outputs value validation
    invalid_metadata_outputs['metadata']['outputs'] = ['good', 100]

    # Test with invalid metadata outputs value
    assert_false(validate_alert(invalid_metadata_outputs))


def test_metadata_non_string_type():
    """Alert Processor Input Validation - Metadata Non-String"""
    # Default valid alert to be modified
    invalid_metadata_non_string = _get_alert()

    # metadata > non-string value validation
    invalid_metadata_non_string['metadata']['type'] = 4.5

    # Test with invalid metadata non-string value
    assert_false(validate_alert(invalid_metadata_non_string))

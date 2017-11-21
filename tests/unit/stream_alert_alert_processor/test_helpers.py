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
from nose.tools import assert_false, assert_true

from stream_alert.alert_processor.helpers import validate_alert
from tests.unit.stream_alert_alert_processor.helpers import get_alert


def test_valid_alert():
    """Alert Processor Input Validation - Valid Alert Structure"""
    # Test with a valid alert structure
    assert_true(validate_alert(get_alert()))


def test_valid_alert_type():
    """Alert Processor Input Validation - Invalid Alert Type"""
    assert_false(validate_alert('not-a-real-alert-object'))


def test_alert_keys():
    """Alert Processor Input Validation - Alert Keys Missing"""
    # Default valid alert to be modified
    missing_alert_key = get_alert()

    # Alter keys to break validation (not all required keys)
    missing_alert_key.pop('rule_name')

    # Test with invalid metadata keys
    assert_false(validate_alert(missing_alert_key))


def test_invalid_record():
    """Alert Processor Input Validation - Invalid Alert Record"""
    # Default valid alert to be modified
    invalid_alert = get_alert()

    # metadata > source value validation
    invalid_alert['record'] = 100

    # Test with invalid metadata source values
    assert_false(validate_alert(invalid_alert))


def test_metadata_source_value():
    """Alert Processor Input Validation - Source Entity Value"""
    # Default valid alert to be modified
    invalid_metadata_source = get_alert()

    # metadata > source value validation
    invalid_metadata_source['source_entity'] = 100

    # Test with invalid metadata source values
    assert_false(validate_alert(invalid_metadata_source))


def test_outputs_type():
    """Alert Processor Input Validation - Metadata Outputs Bad Type"""
    # Default valid alert to be modified
    invalid_metadata_outputs = get_alert()

    # metadata > outputs type validation
    invalid_metadata_outputs['outputs'] = {'bad': 'value'}

    # Test with invalid metadata outputs type
    assert_false(validate_alert(invalid_metadata_outputs))


def test_outputs_value_type():
    """Alert Processor Input Validation - Metadata Outputs Bad Value Type"""
    # Default valid alert to be modified
    invalid_metadata_outputs = get_alert()

    # metadata > outputs value validation
    invalid_metadata_outputs['outputs'] = ['good', 100]

    # Test with invalid metadata outputs value
    assert_false(validate_alert(invalid_metadata_outputs))


def test_metadata_non_string_type():
    """Alert Processor Input Validation - Metadata Non-String"""
    # Default valid alert to be modified
    invalid_metadata_non_string = get_alert()

    # metadata > non-string value validation
    invalid_metadata_non_string['log_type'] = 4.5

    # Test with invalid metadata non-string value
    assert_false(validate_alert(invalid_metadata_non_string))

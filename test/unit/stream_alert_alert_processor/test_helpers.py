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
from copy import deepcopy

from nose.tools import assert_true, assert_false, assert_is_instance

from stream_alert.alert_processor.helpers import (
    validate_alert
)

from unit.stream_alert_alert_processor.helpers import _get_alert

def test_alert_validate_root():
    """Alert Structure Validation"""
    # Default valid alert to be copied/modified
    valid_alert = _get_alert()

    # Test with a valid alert structure
    assert_true(validate_alert(valid_alert))

    # Root key validation
    invalid_root_keys = deepcopy(valid_alert)
    invalid_root_keys.pop('metadata')

    # Test with invalid root keys
    assert_false(validate_alert(invalid_root_keys))

    # Root value validation
    invalid_root_values = deepcopy(valid_alert)
    invalid_root_values['metadata'] = ['value']

    # Test with invalid root values
    assert_false(validate_alert(invalid_root_values))

    # metadata key validation
    invalid_metadata_keys = deepcopy(valid_alert)
    invalid_metadata_keys['metadata'] = {'log': 'osquery'}

    # Test with invalid metadata keys
    assert_false(validate_alert(invalid_metadata_keys))

    # metadata > source key validation
    invalid_metadata_source_01 = deepcopy(valid_alert)
    invalid_metadata_source_01['metadata']['source'] = {'service': 'kinesis'}

    # Test with invalid metadata source keys
    assert_false(validate_alert(invalid_metadata_source_01))

    # metadata > source value validation
    invalid_metadata_source_02 = deepcopy(valid_alert)
    invalid_metadata_source_02['metadata']['source']['entity'] = 100

    # Test with invalid metadata source values
    assert_false(validate_alert(invalid_metadata_source_02))

    # metadata > outputs type validation
    invalid_metadata_outputs = deepcopy(valid_alert)
    invalid_metadata_outputs['metadata']['outputs'] = {'bad': 'value'}

    # Test with invalid metadata outputs type
    assert_false(validate_alert(invalid_metadata_outputs))

    # metadata > outputs value validation
    invalid_metadata_outputs_value = deepcopy(valid_alert)
    invalid_metadata_outputs_value['metadata']['outputs'] = ['good', 100]

    # Test with invalid metadata outputs value
    assert_false(validate_alert(invalid_metadata_outputs_value))

    # metadata > non-string value validation
    invalid_metadata_non_string = deepcopy(valid_alert)
    invalid_metadata_non_string['metadata']['type'] = 4.5

    # Test with invalid metadata non-string value
    assert_false(validate_alert(invalid_metadata_non_string))

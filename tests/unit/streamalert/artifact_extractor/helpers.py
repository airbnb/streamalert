"""
Copyright 2017-present Airbnb, Inc.

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
import json
import base64

from streamalert.shared.normalize import Normalizer

def native_firehose_records(normalized=False, count=2):
    """Generate sample firehose records for unit tests"""
    json_data = [
        {'key_{}'.format(cnt): 'value_{}'.format(cnt)} for cnt in range(count)
    ]

    if normalized:
        for data in json_data:
            data[Normalizer.NORMALIZATION_KEY] = {
                'normalized_type1': {
                    'values': ['value1'],
                    'function': None
                },
                'normalized_type2': {
                    'values': ['value2', 'value3'],
                    'function': None
                }
            }

    return [
        {
            'recordId': 'record_id_{}'.format(cnt),
            'data': base64.b64encode(json.dumps(json_data[cnt]).encode('utf-8')),
            'approximateArrivalTimestamp': 1583275630000+int(cnt)
        } for cnt in range(count)
    ]

def transformed_firehose_records(normalized=False, count=2):
    """Generate sample transformed firehose records for unit tests"""
    json_data = [
        {'key_{}'.format(cnt): 'value_{}'.format(cnt)} for cnt in range(count)
    ]

    if normalized:
        for data in json_data:
            data[Normalizer.NORMALIZATION_KEY] = {
                'normalized_type1': {
                    'values': ['value1'],
                    'function': None
                },
                'normalized_type2': {
                    'values': ['value2', 'value3'],
                    'function': None
                }
            }

    return {
        'records': [
            {
                'result': 'Ok',
                'data': base64.b64encode(json.dumps(json_data[cnt]).encode('utf-8')),
                'recordId': 'record_id_{}'.format(cnt)
            } for cnt in range(count)
        ]
    }

def generate_artifacts():
    """Generate sample artifacts for unit tests"""

    # These values are tight to the result of native_firehose_records() method
    normalized_values = [
        ('normalized_type1', 'value1'),
        ('normalized_type2', 'value2'),
        ('normalized_type2', 'value3'),
        ('normalized_type1', 'value1'),
        ('normalized_type2', 'value2'),
        ('normalized_type2', 'value3')
    ]
    artifacts = [
        {
            'function': 'None',
            'record_id': 'None',
            'source_type': 'unit_test',
            'type': type,
            'value': value,
        } for type, value in normalized_values
    ]

    return [
        json.dumps(artifact, separators=(',', ':')) + '\n' for artifact in artifacts
    ]

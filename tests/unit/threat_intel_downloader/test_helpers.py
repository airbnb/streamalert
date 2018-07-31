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
import json

import boto3
from mock import Mock


def put_mock_params(key, value):
    """Helper function to put mock parameters in parameter store"""
    ssm_client = boto3.client('ssm')
    ssm_client.put_parameter(
        Name=key,
        Value=json.dumps(value),
        Type='SecureString',
        Overwrite=True
    )


def get_mock_context(milliseconds=100):
    """Helper function to create a fake context object using Mock"""
    func_name = 'prefix_threat_intel_downloader'
    arn = 'arn:aws:lambda:us-east-1:123456789012:function:{}:development'
    return Mock(invoked_function_arn=(arn.format(func_name)),
                function_name=func_name,
                get_remaining_time_in_millis=lambda: milliseconds)

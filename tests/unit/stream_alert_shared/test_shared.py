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
from nose.tools import assert_equal

from stream_alert import shared


def test_get_required_outputs():
    """Shared - Get Required Outputs"""

    outputs = shared.get_required_outputs("test")

    assert_equal(len(outputs), 1)
    assert_equal(outputs, {'aws-firehose:alerts': 'test_streamalert_alert_delivery'})

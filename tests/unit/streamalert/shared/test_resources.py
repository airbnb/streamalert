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


from streamalert.shared import resources


def test_get_required_outputs():
    """Shared - Get Required Outputs"""
    outputs = resources.get_required_outputs()
    assert len(outputs) == 1
    assert outputs == {'aws-firehose:alerts'}


def test_merge_required_outputs_dne():
    """Shared - Merge Required Outputs, Does Not Exist"""
    # A simple user config that will be merged with required outputs
    users_config = {
        'aws-s3': {
            'bucket': 'my.s3.bucket'
        },
        'aws-sns': {
            'topic': 'my-sns-topic'
        },
        'slack': [
            'slack_output'
        ]
    }

    outputs = resources.merge_required_outputs(users_config, "test")

    assert len(outputs) == 4

    expected_fh = {
        'alerts': 'test_streamalert_alert_delivery'
    }

    #assert collections.Counter(outputs['aws-firehose']) == collections.Counter(expected_fh)
    assert len(outputs['aws-firehose']) == len(expected_fh)


def test_merge_required_outputs_exists():
    """Shared - Merge Required Outputs, Has Existing"""
    # A simple user config with an exist aws-firehose output
    # that will be merged with required outputs
    users_config = {
        'aws-firehose': {
            'notalerts': 'resource_name'
        },
        'aws-sns': {
            'topic': 'my-sns-topic'
        },
        'slack': [
            'slack_output'
        ]
    }

    outputs = resources.merge_required_outputs(users_config, "test")

    assert len(outputs) == 3

    expected_fh = {
        'notalerts': 'resource_name',
        'alerts': 'test_streamalert_alert_delivery'
    }

    #assert collections.Counter(outputs['aws-firehose']) == collections.Counter(expected_fh)
    assert len(outputs['aws-firehose']) == len(expected_fh)

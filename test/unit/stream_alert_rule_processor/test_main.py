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
from mock import patch

from nose.tools import assert_set_equal

from stream_alert.rule_processor import main

from unit.stream_alert_rule_processor.test_helpers import _get_mock_context


def test_imports():
    """Rule Processor Main - Test Imports"""
    imports = {'matchers.sample',
               'rules.community.cloudtrail.cloudtrail_critical_api',
               'rules.community.cloudtrail.cloudtrail_root_account',
               'rules.community.cloudtrail.cloudtrail_put_bucket_acl',
               'rules.community.cloudtrail.cloudtrail_put_object_acl'}


    assert_set_equal(main.modules_to_import, imports)


@patch('stream_alert.rule_processor.main.StreamAlert.run')
def test_handler(mock_runner):
    """Rule Processor Main - Test Handler"""

    main.handler('event', _get_mock_context())

    mock_runner.assert_called_with('event')

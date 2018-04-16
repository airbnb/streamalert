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
from mock import call, patch

from stream_alert.rule_processor import main


@patch.object(main, 'StreamAlert')
def test_handler(mock_stream_alert):
    """Rule Processor Main - Handler is invoked"""
    main.handler('event', 'context')
    mock_stream_alert.assert_has_calls([
        call('context'),
        call().run('event')
    ])

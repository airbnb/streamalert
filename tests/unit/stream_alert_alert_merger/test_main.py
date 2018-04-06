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
import os

from mock import ANY, call, patch
from moto import mock_dynamodb2, mock_lambda

from stream_alert.alert_merger import main
from stream_alert.shared.alert import Alert
from stream_alert_cli.helpers import create_lambda_function, setup_mock_alerts_table

_ALERTS_TABLE = 'PREFIX_streamalert_alerts'
_ALERT_PROCESSOR = 'PREFIX_streamalert_alert_processor'
_ALERT_PROCESSOR_TIMEOUT_SEC = 60


@mock_dynamodb2
@mock_lambda
class TestAlertMerger(object):
    """Tests for merger/main.py:AlertMerger"""

    @patch.dict(os.environ, {
        'ALERT_PROCESSOR': _ALERT_PROCESSOR,
        'ALERT_PROCESSOR_TIMEOUT_SEC': str(_ALERT_PROCESSOR_TIMEOUT_SEC),
        'ALERTS_TABLE': _ALERTS_TABLE,
        'AWS_DEFAULT_REGION': 'us-east-1'
    })
    def setup(self):
        """Alert Merger - Setup"""
        # pylint: disable=attribute-defined-outside-init
        create_lambda_function(_ALERT_PROCESSOR, 'us-east-1')
        setup_mock_alerts_table(_ALERTS_TABLE)
        self.merger = main.AlertMerger.get_instance()
        self.merger.table.add_alerts([Alert('rule-name', {}, {'output'})])

    @patch.object(main, 'LOGGER')
    def test_dispatch(self, mock_logger):
        """Alert Merger - Dispatch to Alert Processor Lambda"""
        self.merger.dispatch()
        mock_logger.info.assert_called_once_with(
            'Dispatching %s to %s (attempt %d)', ANY, _ALERT_PROCESSOR, 1)


@patch.object(main, 'AlertMerger')
def test_handler(mock_instance):
    """Alert Merger - Handler (Entry Point)"""
    main.handler(None, None)
    mock_instance.assert_has_calls([
        call.get_instance(),
        call.get_instance().dispatch()
    ])

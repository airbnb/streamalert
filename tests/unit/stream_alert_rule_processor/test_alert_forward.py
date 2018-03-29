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

from botocore.exceptions import ClientError
from mock import MagicMock, patch

from stream_alert.rule_processor.alert_forward import AlertForwarder

_ALERTS_TABLE = 'corp-prefix_streamalert_alerts'


class TestAlertForwarder(object):
    """Test class for AlertForwarder"""
    # pylint: disable=attribute-defined-outside-init,protected-access

    @patch('stream_alert.rule_processor.alert_forward.AlertTable', MagicMock())
    @patch.dict(os.environ, {'ALERTS_TABLE': _ALERTS_TABLE})
    def setup(self):
        self.forwarder = AlertForwarder()

    @patch('stream_alert.rule_processor.alert_forward.LOGGER')
    def test_send_alerts(self, mock_logger):
        """AlertForwarder - Send Alerts"""
        self.forwarder.send_alerts([1, 2, 3])
        self.forwarder._table.add_alerts.assert_called_once_with(  # pylint: disable=no-member
            [1, 2, 3])
        mock_logger.info.assert_called_once()

    @patch('stream_alert.rule_processor.alert_forward.LOGGER')
    def test_send_alerts_dynamo_exception(self, mock_logger):
        """AlertForwarder - ClientError When Sending Alerts"""
        self.forwarder._table.add_alerts.side_effect = ClientError({}, 'batch_write')
        self.forwarder.send_alerts([])
        mock_logger.exception.assert_called_once()

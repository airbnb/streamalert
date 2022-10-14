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
import os
from unittest.mock import ANY, MagicMock, Mock, patch

from streamalert.alert_processor.main import AlertProcessor, handler
from streamalert.alert_processor.outputs.output_base import OutputDispatcher
from streamalert.shared.alert import Alert
from streamalert.shared.config import load_config
from streamalert.shared.normalize import Normalizer
from tests.unit.streamalert.alert_processor import ALERTS_TABLE, MOCK_ENV

MOCK_ENV.update({
    'ALERTS_TABLE': ALERTS_TABLE
})


class TestAlertProcessor:
    """Tests for alert_processor/main.py"""
    # pylint: disable=no-member,no-self-use,protected-access

    @patch('streamalert.alert_processor.main.load_config',
           Mock(return_value=load_config('tests/unit/conf/', validate=True)))
    @patch.dict(os.environ, MOCK_ENV)
    @patch.object(AlertProcessor, 'BACKOFF_MAX_TRIES', 1)
    @patch('streamalert.alert_processor.main.AlertTable', MagicMock())
    def setup(self):
        """Alert Processor - Test Setup"""
        # pylint: disable=attribute-defined-outside-init
        self.processor = AlertProcessor()
        self.alert = Alert(
            'hello_world',
            {'abc': 123, Normalizer.NORMALIZATION_KEY: {}},
            {'slack:unit-test-channel'}
        )

    def test_init(self):
        """Alert Processor - Initialization"""
        assert isinstance(self.processor.config, dict)

    @patch('streamalert.alert_processor.main.LOGGER')
    def test_create_dispatcher_invalid(self, mock_logger):
        """Alert Processor - Create Dispatcher - Invalid Output"""
        assert self.processor._create_dispatcher('helloworld') is None
        mock_logger.error.called_once_with(ANY, 'helloworld')

    @patch('streamalert.alert_processor.main.LOGGER')
    def test_create_dispatcher_output_doesnt_exist(self, mock_logger):
        """Alert Processor - Create Dispatcher - Output Does Not Exist"""
        assert self.processor._create_dispatcher('slack:no-such-channel') is None
        mock_logger.error.called_once_with(
            'The output \'%s\' does not exist!', 'slack:no-such-channel')

    @patch.dict(os.environ, MOCK_ENV)
    def test_create_dispatcher(self):
        """Alert Processor - Create Dispatcher - Success"""
        dispatcher = self.processor._create_dispatcher('aws-s3:unit_test_bucket')
        assert isinstance(dispatcher, OutputDispatcher)

    @patch.object(AlertProcessor, '_create_dispatcher')
    def test_send_alerts_success(self, mock_create_dispatcher):
        """Alert Processor - Send Alerts Success"""
        mock_create_dispatcher.return_value.dispatch.return_value = True
        result = self.processor._send_to_outputs(self.alert)
        mock_create_dispatcher.assert_called_once()
        mock_create_dispatcher.return_value.dispatch.assert_called_once()
        assert {'slack:unit-test-channel': True} == result
        assert self.alert.outputs == self.alert.outputs_sent

    @patch.object(AlertProcessor, '_create_dispatcher')
    def test_send_alerts_failure(self, mock_create_dispatcher):
        """Alert Processor - Send Alerts Failure"""
        mock_create_dispatcher.return_value.dispatch.return_value = False
        result = self.processor._send_to_outputs(self.alert)
        mock_create_dispatcher.assert_called_once()
        mock_create_dispatcher.return_value.dispatch.assert_called_once()
        assert {'slack:unit-test-channel': False} == result
        assert set() == self.alert.outputs_sent

    @patch.object(AlertProcessor, '_create_dispatcher', return_value=None)
    def test_send_alerts_skip_invalid_outputs(self, mock_create_dispatcher):
        """Alert Processor - Send Alerts With Invalid Outputs"""
        result = self.processor._send_to_outputs(self.alert)
        mock_create_dispatcher.assert_called_once()
        assert {'slack:unit-test-channel': False} == result

    def test_update_alerts_table_none(self):
        """Alert Processor - Update Alerts Table - Empty Results"""
        self.processor.alerts_table.delete_alert = MagicMock()
        self.processor.alerts_table.update_retry_outputs = MagicMock()
        self.processor._update_table(self.alert, {})
        self.processor.alerts_table.delete_alert.assert_not_called()
        self.processor.alerts_table.update_retry_outputs.assert_not_called()

    def test_update_alerts_table_delete(self):
        """Alert Processor - Update Alerts Table - Delete Item"""
        self.processor._update_table(self.alert, {'out1': True, 'out2': True})
        self.processor.alerts_table.delete_alerts.assert_called_once_with(
            [(self.alert.rule_name, self.alert.alert_id)])

    def test_update_alerts_table_update(self):
        """Alert Processor - Update Alerts Table - Update With Failed Outputs"""
        self.processor._update_table(self.alert, {'out1': True, 'out2': False, 'out3': False})
        self.processor.alerts_table.update_sent_outputs.assert_called_once_with(self.alert)

    @patch.object(AlertProcessor, '_send_to_outputs',
                  return_value={'slack:unit-test-channel': True})
    @patch.object(AlertProcessor, '_update_table')
    def test_run_full_event(self, mock_send_alerts, mock_update_table):
        """Alert Processor - Run With the Full Alert Record"""
        result = self.processor.run(self.alert.dynamo_record())
        assert {'slack:unit-test-channel': True} == result
        mock_send_alerts.assert_called_once()
        mock_update_table.assert_called_once()

    @patch('streamalert.alert_processor.main.LOGGER')
    def test_run_invalid_alert(self, mock_logger):
        """Alert Processor - Run With an Invalid Alert"""
        result = self.processor.run({'Record': 'Nonsense'})
        assert {} == result
        mock_logger.exception.called_once_with('Invalid alert %s', {'Record': 'Nonsense'})

    @patch.object(AlertProcessor, '_send_to_outputs',
                  return_value={'slack:unit-test-channel': True})
    @patch.object(AlertProcessor, '_update_table')
    def test_run_get_alert_from_dynamo(self, mock_send_alerts, mock_update_table):
        """Alert Processor - Run With Just the Alert Key"""
        self.processor.alerts_table.get_alert_record = MagicMock(
            return_value=self.alert.dynamo_record())
        result = self.processor.run(self.alert.dynamo_key)
        assert {'slack:unit-test-channel': True} == result

        self.processor.alerts_table.get_alert_record.assert_called_once_with(
            self.alert.rule_name, self.alert.alert_id)
        mock_send_alerts.assert_called_once()
        mock_update_table.assert_called_once()

    @patch('streamalert.alert_processor.main.LOGGER')
    def test_run_alert_does_not_exist(self, mock_logger):
        """Alert Processor - Run - Alert Does Not Exist"""
        self.processor.alerts_table.get_alert_record = MagicMock(return_value=None)
        self.processor.run(self.alert.dynamo_key)
        mock_logger.error.assert_called_once_with(
            '%s does not exist in the alerts table', self.alert.dynamo_key)

    @patch.dict(os.environ, MOCK_ENV)
    @patch.object(AlertProcessor, 'run', return_value={'output': True})
    def test_handler(self, mock_run):
        """Alert Processor - Lambda Handler"""
        event = {'AlertID': 'abc', 'RuleName': 'hello_world'}
        result = handler(event, None)
        assert {'output': True} == result
        mock_run.assert_called_once_with(event)

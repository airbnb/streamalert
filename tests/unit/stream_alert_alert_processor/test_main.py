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
from collections import OrderedDict
import json
import os

from mock import ANY, call, MagicMock, patch
from moto import mock_dynamodb2
from nose.tools import (
    assert_equal,
    assert_false,
    assert_is_instance,
    assert_is_none,
    assert_true
)

from stream_alert.alert_processor.main import AlertProcessor, handler
from stream_alert.alert_processor.outputs.output_base import OutputDispatcher
from tests.unit.stream_alert_alert_processor import (
    ACCOUNT_ID, ALERTS_TABLE, FUNCTION_NAME, OUTPUT_CONFIG_PATH, PREFIX, REGION)

_ARN = 'arn:aws:lambda:{}:{}:function:{}:production'.format(REGION, ACCOUNT_ID, FUNCTION_NAME)
_EVENT = {
    'AlertID': '00-0-0-00',
    'Cluster': 'corp',
    'Created': '2018-03-14T00:00:00.000Z',
    'LogSource': 'carbonblack:binarystore.file.added',
    'LogType': 'json',
    'Outputs': ['slack:unit_test_channel'],
    'Record': json.dumps({
        'file_path': '/tmp/file.zip',
        'md5': 'ABC'
    }),
    'RuleDescription': 'Info about this rule and what actions to take',
    'RuleName': 'cb_binarystore_file_added',
    'SourceEntity': 'bucket.name',
    'SourceService': 's3'
}


@mock_dynamodb2
@patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1', 'ALERTS_TABLE': ALERTS_TABLE})
@patch.object(AlertProcessor, 'BACKOFF_MAX_TRIES', 1)
@patch.object(AlertProcessor, 'OUTPUT_CONFIG_PATH', OUTPUT_CONFIG_PATH)
class TestAlertProcessor(object):
    """Tests for alert_processor/main.py"""
    # pylint: disable=no-self-use,protected-access

    def test_init(self):
        """Alert Processor - Initialization"""
        processor = AlertProcessor(_ARN)
        assert_is_instance(processor.config, dict)
        assert_equal(processor.region, REGION)
        assert_equal(processor.account_id, ACCOUNT_ID)
        assert_equal(processor.prefix, PREFIX)
        assert_equal(processor.alerts_table.table_name, ALERTS_TABLE)

    def test_build_alert_payload(self):
        """Alert Processor - Building the Alert Payload"""
        payload = AlertProcessor._build_alert_payload(_EVENT)
        assert_is_instance(payload, OrderedDict)
        expected_keys = {
            'cluster', 'created', 'id', 'log_source', 'log_type', 'outputs', 'record',
            'rule_description', 'rule_name', 'source_entity', 'source_service'
        }
        assert_equal(expected_keys, set(payload.keys()))

    @patch('stream_alert.alert_processor.main.LOGGER')
    def test_create_dispatcher_invalid(self, mock_logger):
        """Alert Processor - Create Dispatcher - Invalid Output"""
        processor = AlertProcessor(_ARN)
        assert_is_none(processor._create_dispatcher('helloworld'))
        mock_logger.error.called_once_with(ANY, 'helloworld')

    @patch('stream_alert.alert_processor.main.LOGGER')
    def test_create_dispatcher_output_doesnt_exist(self, mock_logger):
        """Alert Processor - Create Dispatcher - Output Does Not Exist"""
        processor = AlertProcessor(_ARN)
        assert_is_none(processor._create_dispatcher('slack:no-such-channel'))
        mock_logger.error.called_once_with(
            'The output \'%s\' does not exist!', 'slack:no-such-channel')

    def test_create_dispatcher(self):
        """Alert Processor - Create Dispatcher - Success"""
        processor = AlertProcessor(_ARN)
        dispatcher = processor._create_dispatcher('aws-s3:unit_test_bucket')
        assert_is_instance(dispatcher, OutputDispatcher)

    @patch('stream_alert.alert_processor.main.LOGGER')
    def test_send_alert_exception(self, mock_logger):
        """Alert Processor - Send Alert - Exception"""
        dispatcher = MagicMock()
        dispatcher.dispatch.side_effect = AttributeError
        alert = {'id': '123', 'rule_name': 'hello_world', 'record': {'abc': 123}}

        assert_false(AlertProcessor._send_alert(alert, 'slack:unit_test_channel', dispatcher))
        mock_logger.assert_has_calls([
            call.info('Sending alert %s to %s', '123', 'slack:unit_test_channel'),
            call.exception('Exception when sending alert %s to %s. Alert:\n%s',
                           '123', 'slack:unit_test_channel', ANY)
        ])

    @patch('stream_alert.alert_processor.main.LOGGER')
    def test_send_alert(self, mock_logger):
        """Alert Processor - Send Alert - Success"""
        dispatcher = MagicMock()
        dispatcher.dispatch.return_value = True
        alert = {'id': '123', 'rule_name': 'hello_world', 'record': {'abc': 123}}

        assert_true(AlertProcessor._send_alert(alert, 'slack:unit_test_channel', dispatcher))
        dispatcher.dispatch.assert_called_once_with(
            descriptor='unit_test_channel', rule_name='hello_world', alert=alert)
        mock_logger.info.assert_called_once_with(
            'Sending alert %s to %s', '123', 'slack:unit_test_channel')

    def test_update_alerts_table_delete(self):
        """Alert Processor - Update Alerts Table - Delete Item"""
        processor = AlertProcessor(_ARN)
        processor.alerts_table.delete_item = MagicMock()

        processor._update_alerts_table('name', 'id', {'out1': True, 'out2': True})
        processor.alerts_table.delete_item.assert_called_once_with(
            Key={'RuleName': 'name', 'AlertID': 'id'}
        )

    def test_update_alerts_table_update(self):
        """Alert Processor - Update Alerts Table - Update With Failed Outputs"""
        processor = AlertProcessor(_ARN)
        processor.alerts_table.update_item = MagicMock()

        processor._update_alerts_table('name', 'id', {'out1': True, 'out2': False, 'out3': False})
        processor.alerts_table.update_item.assert_called_once_with(
            Key={'RuleName': 'name', 'AlertID': 'id'},
            UpdateExpression='SET RetryOutputs = :failed_outputs',
            ExpressionAttributeValues={':failed_outputs': {'out2', 'out3'}}
        )

    @patch.object(AlertProcessor, '_send_alert', return_value=True)
    @patch.object(AlertProcessor, '_update_alerts_table')
    def test_run(self, mock_send_alert, mock_update_table):
        """Alert Processor - Run"""
        processor = AlertProcessor(_ARN)
        results = processor.run(_EVENT)

        mock_send_alert.assert_called_once()
        mock_update_table.assert_called_once()
        assert_equal({'slack:unit_test_channel': True}, results)

    @patch.object(AlertProcessor, 'run', return_value={'out1': True})
    def test_handler(self, mock_run):
        """Alert Processor - Lambda Handler"""
        context = MagicMock()
        context.invoked_function_arn = _ARN

        result = handler(_EVENT, context)
        mock_run.assert_called_once_with(_EVENT)
        assert_equal({'out1': True}, result)

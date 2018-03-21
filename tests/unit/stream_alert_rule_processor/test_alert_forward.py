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
from mock import ANY, call, patch
from moto import mock_dynamodb2
from nose.tools import assert_equal

from stream_alert.rule_processor.alert_forward import AlertForwarder
from stream_alert.rule_processor.config import load_env
from tests.unit.stream_alert_rule_processor.test_helpers import get_mock_context

_MOCK_ALERT = {
    'id': 'test-uuid',
    'log_source': 'test_source',
    'log_type': 'test_type',
    'record': {
        'key': 'value'
    },
    'outputs': ['out1:here', 'out1:here', 'out2:there'],
    'rule_description': 'Test Description',
    'rule_name': 'test_name',
    'source_entity': 'test_entity',
    'source_service': 'test_service'
}
_ALERT_TABLE = 'corp-prefix_streamalert_alerts'
_CLUSTER = 'corp'


@patch.dict(os.environ, {'CLUSTER': _CLUSTER})
class TestAlertForwarder(object):
    """Test class for AlertForwarder"""
    # pylint: disable=no-self-use,protected-access

    @patch.dict(os.environ, {'ALERTS_TABLE': _ALERT_TABLE})
    def setup(self):
        # pylint: disable=attribute-defined-outside-init
        self.forwarder = AlertForwarder(load_env(get_mock_context()))

    def test_alert_item(self):
        """AlertForwarder - Convert Alert to Dynamo Item"""
        item = AlertForwarder.dynamo_record(_MOCK_ALERT)
        expected = {
            'RuleName': 'test_name',
            'AlertID': 'test-uuid',
            'Created': ANY,
            'Cluster': _CLUSTER,
            'LogSource': 'test_source',
            'LogType': 'test_type',
            'RuleDescription': 'Test Description',
            'SourceEntity': 'test_entity',
            'SourceService': 'test_service',
            'Outputs': {'out1:here', 'out2:there'},  # Duplicates are ignored
            'Record': '{"key":"value"}'
        }
        assert_equal(expected, item)

    @mock_dynamodb2()
    @patch('stream_alert.rule_processor.alert_forward.LOGGER')
    def test_send_alerts(self, mock_logger):
        """AlertForwarder - Send Alerts"""
        self.forwarder.send_alerts([_MOCK_ALERT] * 2)
        mock_logger.assert_has_calls([
            call.info('Successfully sent %d alert(s) to dynamo:%s', 2, _ALERT_TABLE)
        ])

    @patch.object(AlertForwarder, '_send_to_dynamo')
    @patch('stream_alert.rule_processor.alert_forward.LOGGER')
    def test_send_alerts_dynamo_exception(self, mock_logger, mock_dynamo):
        """AlertForwarder - Send Alerts with Dynamo Exception"""
        mock_dynamo.side_effect = ClientError({}, 'batch_write')
        self.forwarder.send_alerts(None)

        mock_dynamo.assert_called_once_with(None)
        mock_logger.assert_has_calls([
            call.exception('Error saving alerts to Dynamo')
        ])

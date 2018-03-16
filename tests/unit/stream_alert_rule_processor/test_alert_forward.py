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
# pylint: disable=no-self-use,protected-access
from datetime import datetime
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


@patch.dict(os.environ, {'CLUSTER': 'corp'})
class TestAlertForwarder(object):
    """Test class for AlertForwarder"""
    ALERT_PROCESSOR = 'corp-prefix_streamalert_alert_processor'
    ALERTS_TABLE = 'corp-prefix_streamalert_alerts'

    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        patcher = patch('boto3.client')
        cls.boto_mock = patcher.start()
        context = get_mock_context()
        env = load_env(context)
        with patch.dict(os.environ, {'ALERT_PROCESSOR': cls.ALERT_PROCESSOR,
                                     'ALERTS_TABLE': cls.ALERTS_TABLE}):
            cls.forwarder = AlertForwarder(env)

    @classmethod
    def teardown_class(cls):
        """Teardown the class after any methods"""
        cls.forwarder = None
        cls.boto_mock.stop()

    def teardown(self):
        """Teardown the class after each methods"""
        self.forwarder.env['lambda_alias'] = 'development'

    @patch('stream_alert.rule_processor.alert_forward.LOGGER')
    def test_lambda_boto_error(self, log_mock):
        """AlertForwarder - Lambda - Boto Error"""

        err_response = {'Error': {'Code': 100}}

        # Add ClientError side_effect to mock
        self.boto_mock.return_value.invoke.side_effect = ClientError(
            err_response, 'operation')

        self.forwarder.send_alerts(['alert!!!'])

        log_mock.assert_has_calls([
            call.exception(
                'An error occurred while sending alert to \'%s:production\'. '
                'Error is: %s. Alert: %s', self.ALERT_PROCESSOR,
                err_response, '"alert!!!"'
            ),
            call.exception('Error saving alerts to Dynamo')
        ])

    @patch('stream_alert.rule_processor.alert_forward.LOGGER')
    def test_lambda_resp_error(self, log_mock):
        """AlertForwarder - Lambda - Boto Response Error"""
        self.boto_mock.return_value.invoke.side_effect = [{
            'ResponseMetadata': {'HTTPStatusCode': 201}}]

        self.forwarder.send_alerts(['alert!!!'])

        log_mock.assert_has_calls([
            call.error('Failed to send alert to \'%s\': %s', self.ALERT_PROCESSOR, '"alert!!!"'),
            call.exception('Error saving alerts to Dynamo')
        ])

    @patch('stream_alert.rule_processor.alert_forward.LOGGER')
    def test_lambda_success(self, log_mock):
        """AlertForwarder - Lambda - Success"""
        self.boto_mock.return_value.invoke.side_effect = [{
            'ResponseMetadata': {
                'HTTPStatusCode': 202,
                'RequestId': 'reqID'
            }
        }]

        # Swap out the alias so the logging occurs
        self.forwarder.env['lambda_alias'] = 'production'

        self.forwarder.send_alerts(['alert!!!'])

        log_mock.assert_has_calls([
            call.info('Sent alert to \'%s\' with Lambda request ID \'%s\'',
                      self.ALERT_PROCESSOR, 'reqID')
        ])

    @patch('stream_alert.rule_processor.alert_forward.LOGGER')
    def test_lambda_bad_obj(self, log_mock):
        """AlertForwarder - Lambda - JSON Dump Bad Object"""
        bad_object = datetime.utcnow()
        self.forwarder.send_alerts([bad_object])

        log_mock.assert_has_calls([
            call.error('An error occurred while dumping alert to JSON: %s Alert: %s',
                       '\'datetime.datetime\' object has no attribute \'__dict__\'', bad_object),
            call.exception('Error saving alerts to Dynamo')
        ])

    def test_dynamo_record(self):
        """AlertForwarder - Convert Alert to Dynamo Item"""
        record = AlertForwarder.dynamo_record(_MOCK_ALERT)
        expected = {
            'RuleName': 'test_name',
            'AlertID': 'test-uuid',
            'Created': ANY,
            'Cluster': 'corp',
            'LogSource': 'test_source',
            'LogType': 'test_type',
            'RuleDescription': 'Test Description',
            'SourceEntity': 'test_entity',
            'SourceService': 'test_service',
            'Outputs': {'out1:here', 'out2:there'},  # Duplicates are ignored
            'Record': '{"key":"value"}'
        }
        assert_equal(expected, record)

    @mock_dynamodb2()
    @patch('stream_alert.rule_processor.alert_forward.LOGGER')
    def test_send_to_dynamo(self, mock_logger):
        """AlertForwarder - Send Alerts"""
        self.forwarder._send_to_dynamo([_MOCK_ALERT] * 2)
        mock_logger.assert_has_calls([
            call.info('Successfully sent %d alerts to dynamo:%s', 2, self.ALERTS_TABLE)
        ])

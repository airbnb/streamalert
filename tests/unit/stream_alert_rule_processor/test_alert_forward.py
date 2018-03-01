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
# pylint: disable=protected-access
from datetime import datetime
import os

from botocore.exceptions import ClientError
from mock import ANY, call, patch
from nose.tools import assert_equal

from stream_alert.rule_processor.alert_forward import AlertForwarder
from stream_alert.rule_processor.config import load_env
from tests.unit.stream_alert_rule_processor.test_helpers import get_mock_context


@patch.object(AlertForwarder, 'BACKOFF_MAX_RETRIES', 1)
@patch.dict(os.environ, {'CLUSTER': 'corp'})
class TestAlertForwarder(object):
    """Test class for AlertForwarder"""
    ALERT_PROCESSOR = 'corp-prefix_streamalert_alert_processor'
    ALERT_TABLE = 'corp-prefix_streamalert_alerts'

    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        patcher = patch('boto3.client')
        cls.boto_mock = patcher.start()
        context = get_mock_context()
        env = load_env(context)
        with patch.dict(os.environ, {'ALERT_PROCESSOR': cls.ALERT_PROCESSOR,
                                     'ALERT_TABLE': cls.ALERT_TABLE}):
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

    @staticmethod
    def _generate_alerts(count):
        """Generate a list of alert dictionaries."""
        return [
            {
                'record': '{"abc": 123}',
                'rule_description': 'Desc{}'.format(i),
                'rule_name': 'Rule{}'.format(i),
                'outputs': ['aws-lambda:...', 'aws-s3:...']
            }
            for i in xrange(count)
        ]

    def test_alert_batches_single_alert(self):
        """AlertForwarder - Alert Batching - Single Alert"""
        alerts = self._generate_alerts(1)
        result = list(self.forwarder._alert_batches(alerts))

        expected = [
            {
                self.ALERT_TABLE: [
                    {
                        'PutRequest': {
                            'Item': {
                                'RuleName': {'S': 'Rule0'},
                                'Timestamp': {'S': ANY},
                                'Cluster': {'S': 'corp'},
                                'RuleDescription': {'S': 'Desc0'},
                                'Outputs': {'SS': ['aws-lambda:...', 'aws-s3:...']},
                                'Record': {'S': '"{\\"abc\\": 123}"'},
                                'TTL': {'N': ANY}
                            }
                        }
                    }
                ]
            }
        ]
        assert_equal(expected, result)

    def test_alert_batches_max_batch(self):
        """AlertForwarder - Alert Batching - Full Batch"""
        alerts = self._generate_alerts(10)
        result = list(self.forwarder._alert_batches(alerts, batch_size=10))

        assert_equal(1, len(result))  # There should be one batch.
        assert_equal(10, len(result[0][self.ALERT_TABLE]))  # All 10 alerts should be in the batch.

    def test_alert_batches_max_batch_plus_one(self):
        """AlertForwarder - Alert Batching - Full Batch + 1"""
        alerts = self._generate_alerts(11)
        result = list(self.forwarder._alert_batches(alerts, batch_size=10))

        assert_equal(2, len(result))  # There should be 2 alert batches.
        assert_equal(10, len(result[0][self.ALERT_TABLE]))  # 10 alerts in the first batch.
        assert_equal(1, len(result[1][self.ALERT_TABLE]))  # 1 alert in the second batch.

    @patch('stream_alert.rule_processor.alert_forward.LOGGER')
    @patch('stream_alert.rule_processor.alert_forward.MetricLogger.log_metric')
    def test_dynamo_unprocessed_alerts(self, metric_log_mock, log_mock):
        """AlertForwarder - Dynamo - Retry unprocessed alerts"""

        def mock_batch_write_item(**kwargs):
            """Mock client_dynamo.batch_write_item to always return all items unprocessed."""
            return {
                'ResponseMetadata': {'HTTPStatusCode': 200},
                'UnprocessedItems': kwargs['RequestItems']
            }

        self.boto_mock.return_value.batch_write_item.side_effect = mock_batch_write_item

        self.forwarder._send_to_dynamo(self._generate_alerts(30))

        log_mock.assert_has_calls([
            call.info('Sending batch %d to Dynamo with %d alert(s)', 1, 25),
            call.error('Unable to save alert batch; unprocessed items remain: %s', ANY),
            call.info('Sending batch %d to Dynamo with %d alert(s)', 2, 5),
            call.error('Unable to save alert batch; unprocessed items remain: %s', ANY)
        ])
        metric_log_mock.assert_has_calls([
            call('rule_processor', 'UnprocessedAlerts', 25),
            call('rule_processor', 'UnprocessedAlerts', 5)
        ])

    @patch('stream_alert.rule_processor.alert_forward.LOGGER')
    def test_dynamo_successful(self, log_mock):
        """AlertForwarder - Dynamo - Successful"""
        self.boto_mock.return_value.batch_write_item.return_value = {
            'ResponseMetadata': {'HTTPStatusCode': 200},
            'UnprocessedItems': {}
        }

        self.forwarder._send_to_dynamo(self._generate_alerts(1))

        log_mock.assert_has_calls([call.info('Sending batch %d to Dynamo with %d alert(s)', 1, 1)])

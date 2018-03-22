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
from decimal import Decimal
import json
import os

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from mock import ANY, call, patch, MagicMock
from moto import mock_dynamodb2, mock_lambda
from nose.tools import assert_equal, assert_is_instance, assert_raises

from stream_alert.alert_merger import main
from stream_alert_cli.helpers import create_lambda_function, setup_mock_alerts_table

_ALERTS_TABLE = 'PREFIX_streamalert_alerts'
_ALERT_PROCESSOR = 'PREFIX_streamalert_alert_processor'
_ALERT_PROCESSOR_TIMEOUT_SEC = 60


class TestAlertTable(object):
    """Tests for merger/main.py:AlertTable"""

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Alert Merger - Alert Table - Add mock alerts to the table"""
        # pylint: disable=attribute-defined-outside-init
        self.dynamo_mock = mock_dynamodb2()
        self.dynamo_mock.start()

        setup_mock_alerts_table(_ALERTS_TABLE)
        self.alert_table = main.AlertTable(_ALERTS_TABLE)

        with self.alert_table.table.batch_writer() as batch:
            for i in range(3):
                batch.put_item(Item={
                    'RuleName': 'even' if i % 2 == 0 else 'odd',
                    'AlertID': 'alert-{}'.format(str(i)),
                    'Created': '2018-03-14',
                    'Cluster': 'test-cluster',
                    'LogSource': 'test-log-source',
                    'LogType': 'json',
                    'RuleDescription': 'even' if i % 2 == 0 else 'odd',
                    'SourceEntity': 'test-source-entity',
                    'SourceService': 'test-source-service',
                    'Outputs': {'aws-s3:test-bucket', 'slack:test-channel'},
                    'Record': json.dumps({
                        'key1': 'value1',
                        'key2': 'value2'
                    })
                })

    def teardown(self):
        """Alert Merger - Teardown - Stop Mocks"""
        self.dynamo_mock.stop()

    def test_paginate_multiple(self):
        """Alert Merger - Alert Table - Paginate Traverses Multiple Pages"""
        def mock_table_op(**kwargs):
            """Returns two pages of mock results (moto's dynamo does not paginate)"""
            if 'ExclusiveStartKey' in kwargs:
                return {'Items': [2]}
            return {'Items': [1], 'LastEvaluatedKey': 'somewhere'}
        results = list(self.alert_table._paginate(mock_table_op, {}))
        assert_equal([1, 2], results)

    def test_rule_names(self):
        """Alert Merger - Alert Table - Rule Names From Table Scan"""
        assert_equal({'even', 'odd'}, self.alert_table.rule_names())

    def test_pending_alerts(self):
        """Alert Merger - Alert Table - Pending Alerts From Table Query"""
        alerts = list(self.alert_table.pending_alerts('odd', _ALERT_PROCESSOR_TIMEOUT_SEC))
        assert_equal(1, len(alerts))
        assert_equal('odd', alerts[0]['RuleName'])
        assert_equal('alert-1', alerts[0]['AlertID'])

    def test_mark_as_dispatched(self):
        """Alert Merger - Alert Table - Mark Alert As Dispatched"""
        self.alert_table.mark_as_dispatched('even', 'alert-2')

        # Verify that there are now Attempts and Dispatched keys
        response = self.alert_table.table.query(
            KeyConditionExpression=Key('RuleName').eq('even') & Key('AlertID').eq('alert-2'))
        item = response['Items'][0]
        assert_equal(Decimal('1'), item['Attempts'])
        assert_is_instance(item['Dispatched'], Decimal)

    def test_mark_as_dispatched_conditional_fail(self):
        """Alert Merger - Alert Table - Dispatched Alert is Already Deleted"""
        self.alert_table.table = MagicMock()

        def mock_update(**kwargs):  # pylint: disable=unused-argument
            raise ClientError({'Error': {'Code': 'ConditionalCheckFailedException'}}, 'UpdateItem')
        self.alert_table.table.update_item.side_effect = mock_update

        # No error should be raised if the conditional delete failed
        self.alert_table.mark_as_dispatched('rule_name', 'alert_id')
        self.alert_table.table.update_item.assert_called_once_with(
            Key={'RuleName': 'rule_name', 'AlertID': 'alert_id'},
            UpdateExpression='SET Dispatched = :now ADD Attempts :one',
            ExpressionAttributeValues={':now': ANY, ':one': 1},
            ConditionExpression='attribute_exists(AlertID)'
        )

    def test_mark_as_dispatched_exception(self):
        """Alert Merger - Alert Table - An Unhandled Exception is Re-Raised"""
        self.alert_table.table = MagicMock()

        def mock_update(**kwargs):  # pylint: disable=unused-argument
            raise ClientError({'Error': {'Code': 'TEST'}}, 'UpdateItem')
        self.alert_table.table.update_item.side_effect = mock_update

        assert_raises(ClientError, self.alert_table.mark_as_dispatched, '', '')


class TestAlertEncoder(object):
    """Tests for merger/main.py:AlertEncoder"""

    def test_to_json(self):
        """Alert Merger - Alert Encoder - JSON Encoding for Set and Decimal"""
        data = {'letter': {'a'}, 'number': {Decimal('1')}}
        result = json.dumps(data, cls=main.AlertEncoder, sort_keys=True)
        assert_equal('{"letter": ["a"], "number": [1.0]}', result)

    def test_to_json_invalid(self):
        """Alert Merger - Alert Encoder - TypeError is raised when appropriate"""
        assert_raises(TypeError, json.dumps, object, cls=main.AlertEncoder)


@mock_lambda
class TestAlertMerger(object):
    """Tests for merger/main.py:AlertMerger"""

    @patch.dict(os.environ, {
        'ALERT_PROCESSOR': _ALERT_PROCESSOR,
        'ALERT_PROCESSOR_TIMEOUT_SEC': str(_ALERT_PROCESSOR_TIMEOUT_SEC),
        'ALERTS_TABLE': _ALERTS_TABLE,
        'AWS_DEFAULT_REGION': 'us-east-1'
    })
    @patch.object(main, 'AlertTable', MagicMock())
    def setup(self):
        """Alert Merger - Setup - Create AlertMerger instance and mock alert processor"""
        # pylint: disable=attribute-defined-outside-init
        self.merger = main.AlertMerger()
        create_lambda_function(_ALERT_PROCESSOR, 'us-east-1')

    @patch.object(main, 'LOGGER')
    def test_dispatch(self, mock_logger):
        """Alert Merger - Alert Merger - Dispatch to Alert Processor Lambda"""
        self.merger.alerts_db.rule_names.return_value = ['name']
        self.merger.alerts_db.pending_alerts.return_value = [{'AlertID': 'id', 'RuleName': 'name'}]

        self.merger.dispatch()
        mock_logger.info.assert_called_once_with(
            'Dispatching alert %s to %s (attempt %d)', 'id', _ALERT_PROCESSOR, 1)


@patch.object(main, 'AlertMerger')
def test_handler(mock_instance):
    """Alert Merger - Handler (Entry Point)"""
    main.handler(None, None)
    mock_instance.assert_has_calls([
        call.get_instance(),
        call.get_instance().dispatch()
    ])

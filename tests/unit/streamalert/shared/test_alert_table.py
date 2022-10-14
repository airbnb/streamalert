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
from datetime import datetime
from unittest.mock import ANY, MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from moto import mock_dynamodb

from streamalert.shared import alert as alert_module
from streamalert.shared import alert_table
from tests.unit.helpers.aws_mocks import setup_mock_alerts_table

_ALERTS_TABLE = 'PREFIX_streamalert_alerts'
_ALERT_PROCESSOR_TIMEOUT_SEC = 60


class TestAlertTable:
    """Tests for shared/alert_table.py"""
    # pylint: disable=protected-access

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Alert Table - Create mock table and alerts"""
        # pylint: disable=attribute-defined-outside-init
        self.dynamo_mock = mock_dynamodb()
        self.dynamo_mock.start()

        setup_mock_alerts_table(_ALERTS_TABLE)
        self.alert_table = alert_table.AlertTable(_ALERTS_TABLE)

        self.alerts = [
            alert_module.Alert(
                'even' if i % 2 == 0 else 'odd',
                {'key1': 'value1', 'key2': 'value2'},
                {'aws-firehose:alerts', 'aws-s3:test-bucket', 'slack:test-channel'},
            )
            for i in range(3)
        ]
        self.alert_table.add_alerts(self.alerts)

    def teardown(self):
        """Alert Table - Teardown - Stop Mocks"""
        self.dynamo_mock.stop()

    def test_name(self):
        """Alert Table - Name Property"""
        assert _ALERTS_TABLE == self.alert_table.name

    def test_paginate_multiple(self):
        """Alert Table - Paginate Traverses Multiple Pages"""
        def mock_table_op(**kwargs):
            """Returns two pages of mock results (moto's dynamo does not paginate)"""
            if 'ExclusiveStartKey' in kwargs:
                return {'Items': [2]}
            return {'Items': [1], 'LastEvaluatedKey': 'somewhere'}
        results = list(self.alert_table._paginate(mock_table_op, {}))
        assert [1, 2] == results

    def test_rule_names_generator(self):
        """Alert Table - Rule Names Generator From Table Scan"""
        assert {'even', 'odd'} == set(self.alert_table.rule_names_generator())

    def test_get_alert_records(self):
        """Alert Table - Pending Alerts From Table Query"""
        result = list(self.alert_table.get_alert_records('odd', _ALERT_PROCESSOR_TIMEOUT_SEC))
        assert 1 == len(result)
        # All the properties should be the same between the two alerts
        assert self.alerts[1].dynamo_record() == result[0]

    def test_get_alert_record(self):
        """Alert Table - Get a Single Alert"""
        result = self.alert_table.get_alert_record(
            self.alerts[0].rule_name, self.alerts[0].alert_id)
        assert self.alerts[0].dynamo_record() == result

    def test_add_alerts(self):
        """Alert Table - Add Alerts"""
        items = self.alert_table._table.scan()['Items']
        assert 3 == len(items)

    def test_mark_as_dispatched(self):
        """Alert Table - Mark As Dispatched"""
        alert = self.alerts[1]
        alert.attempts = 1
        alert.dispatched = datetime.utcnow()
        self.alert_table.mark_as_dispatched(alert)

        # Verify that there is now 1 attempt
        result = self.alert_table.get_alert_record(alert.rule_name, alert.alert_id)
        assert 1 == result['Attempts']

    def test_mark_as_dispatched_conditional_fail(self):
        """Alert Table - Mark As Dispatched - Alert is Already Deleted"""
        self.alert_table._table = MagicMock()

        def mock_update(**kwargs):  # pylint: disable=unused-argument
            raise ClientError({'Error': {'Code': 'ConditionalCheckFailedException'}}, 'UpdateItem')
        self.alert_table._table.update_item.side_effect = mock_update

        # No error should be raised if the conditional delete failed
        alert = self.alerts[1]
        alert.attempts = 1
        alert.dispatched = datetime.utcnow()
        self.alert_table.mark_as_dispatched(alert)
        self.alert_table._table.update_item.assert_called_once_with(
            Key={'RuleName': alert.rule_name, 'AlertID': alert.alert_id},
            UpdateExpression='SET Attempts = :attempts, Dispatched = :dispatched',
            ExpressionAttributeValues={':attempts': 1, ':dispatched': ANY},
            ConditionExpression='attribute_exists(AlertID)'
        )

    def test_mark_as_dispatched_exception(self):
        """Alert Table - Mark As Dispatched - An Unhandled Exception is Re-Raised"""
        self.alert_table._table = MagicMock()

        def mock_update(**kwargs):  # pylint: disable=unused-argument
            raise ClientError({'Error': {'Code': 'TEST'}}, 'UpdateItem')
        self.alert_table._table.update_item.side_effect = mock_update

        pytest.raises(ClientError, self.alert_table.mark_as_dispatched, self.alerts[0])

    def test_update_sent_outputs(self):
        """Alert Table - Update Retry Outputs"""
        alert = self.alerts[0]
        alert.sent_outputs = {'aws-s3:test-bucket'}
        self.alert_table.update_sent_outputs(alert)
        # Nothing else to verify - moto apparently doesn't support set updates

    def test_update_sent_outputs_unhandled_exception(self):
        """Alert Table - Update Retry Outputs - An Unhandled Exception is Re-Raised"""
        self.alert_table._table = MagicMock()

        def mock_update(**kwargs):  # pylint: disable=unused-argument
            raise ClientError({'Error': {'Code': 'TEST'}}, 'UpdateItem')
        self.alert_table._table.update_item.side_effect = mock_update

        pytest.raises(ClientError, self.alert_table.update_sent_outputs, self.alerts[0])

    def test_delete_alert(self):
        """Alert Table - Delete Alert"""
        self.alert_table.delete_alerts([(alert.rule_name, alert.alert_id) for alert in self.alerts])
        assert 0 == len(self.alert_table._table.scan()['Items'])

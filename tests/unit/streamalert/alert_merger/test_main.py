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
# pylint: disable=attribute-defined-outside-init,no-self-use,protected-access
from datetime import datetime, timedelta
from unittest.mock import ANY, MagicMock, call, patch

from moto import mock_dynamodb, mock_lambda

from streamalert.alert_merger import main
from streamalert.shared.alert import Alert
from tests.unit.helpers.aws_mocks import (create_lambda_function,
                                          setup_mock_alerts_table)

_ALERTS_TABLE = 'PREFIX_streamalert_alerts'
_ALERT_PROCESSOR = 'PREFIX_streamalert_alert_processor'
_ALERT_PROCESSOR_TIMEOUT_SEC = 60


class TestAlertMergeGroup:
    """Tests for merger/main.py:AlertMergeGroup class"""

    def test_add_mergeable(self):
        """Alert Merger - Merge Group - Add Alert to Group"""
        alert = Alert('', {'key': True}, set(),
                      merge_by_keys=['key'], merge_window=timedelta(minutes=5))
        group = main.AlertMergeGroup(alert)
        assert group.add(alert)  # An alert can always merge with itself
        assert [alert, alert] == group.alerts

    def test_add_not_mergeable(self):
        """Alert Merger - Merge Group - Did Not Add Alert to Group"""
        alert1 = Alert('', {'key': True}, set(),
                       merge_by_keys=['key'], merge_window=timedelta(minutes=5))
        alert2 = Alert('', {'key': True}, set(),
                       merge_by_keys=['other'], merge_window=timedelta(minutes=5))
        group = main.AlertMergeGroup(alert1)
        assert not group.add(alert2)
        assert [alert1] == group.alerts


class TestAlertMerger:
    """Tests for merger/main.py:AlertMerger class"""

    @patch.dict(os.environ, {
        'ALERT_PROCESSOR': _ALERT_PROCESSOR,
        'ALERT_PROCESSOR_TIMEOUT_SEC': str(_ALERT_PROCESSOR_TIMEOUT_SEC),
        'ALERTS_TABLE': _ALERTS_TABLE,
        'AWS_DEFAULT_REGION': 'us-east-1'
    })
    def setup(self):
        """Alert Merger - Setup"""
        self.dynamo_mock = mock_dynamodb()
        self.lambda_mock = mock_lambda()
        self.dynamo_mock.start()
        self.lambda_mock.start()

        create_lambda_function(_ALERT_PROCESSOR, 'us-east-1')
        setup_mock_alerts_table(_ALERTS_TABLE)
        self.merger = main.AlertMerger.get_instance()

    def teardown(self):
        """Alert Merger - Teardown (Stop Mocks)"""
        self.dynamo_mock.stop()
        self.lambda_mock.stop()

    @patch.object(main, 'LOGGER')
    def test_alert_generator(self, mock_logger):
        """Alert Merger - Sorted Alerts - Invalid Alerts are Logged"""
        records = [
            Alert('test_rule', {}, {'output'}).dynamo_record(),
            {'Nonsense': 'Record'}
        ]

        with patch.object(self.merger.table, 'get_alert_records', return_value=records):
            result = list(self.merger._alert_generator('test_rule'))
            # Valid record is returned
            assert 1 == len(result)
            assert records[0]['AlertID'] == result[0].alert_id
            # Invalid record logs an exception
            mock_logger.exception.assert_called_once_with('Invalid alert record %s', records[1])

    def test_merge_groups_too_recent(self):
        """Alert Merger - Alert Collection - All Alerts Too Recent to Merge"""
        alerts = [
            Alert('', {'key': True}, set(),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=10))
        ]
        assert [] == main.AlertMerger._merge_groups(alerts)

    def test_merge_groups_single(self):
        """Alert Merger - Alert Collection - Single Merge Group"""
        alerts = [
            Alert('', {'key': True}, set(),
                  created=datetime(year=2000, month=1, day=1),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=5)),
            Alert('', {'key': True, 'other': True}, set(),
                  created=datetime(year=2000, month=1, day=1),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=5))
        ]

        groups = main.AlertMerger._merge_groups(alerts)
        assert 1 == len(groups)
        assert alerts == groups[0].alerts

    def test_merge_groups_complex(self):
        """Alert Merger - Alert Collection - Complex Merge Groups"""
        alerts = [
            # Merge group 1 - key 'A' minutes 0-5
            Alert('same_rule_name', {'key': 'A'}, set(),
                  created=datetime(year=2000, month=1, day=1),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=5)),
            Alert('same_rule_name', {'key': 'A'}, set(),
                  created=datetime(year=2000, month=1, day=1, minute=1),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=5)),

            # Merge group 2 - Key B minutes 0-5
            Alert('same_rule_name', {'key': 'B'}, set(),
                  created=datetime(year=2000, month=1, day=1, minute=2),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=5)),
            Alert('same_rule_name', {'key': 'B'}, set(),
                  created=datetime(year=2000, month=1, day=1, minute=2, second=30),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=5)),
            Alert('same_rule_name', {'key': 'B'}, set(),
                  created=datetime(year=2000, month=1, day=1, minute=3),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=5)),

            # Merge group 3 - Different merge keys
            Alert('same_rule_name', {'key': 'A', 'other': 'B'}, set(),
                  created=datetime(year=2000, month=1, day=1, minute=4),
                  merge_by_keys=['key', 'other'], merge_window=timedelta(minutes=5)),
            Alert('same_rule_name', {'key': 'A', 'other': 'B'}, set(),
                  created=datetime(year=2000, month=1, day=1, minute=5),
                  merge_by_keys=['key', 'other'], merge_window=timedelta(minutes=5)),

            # Merge group 4 - key A minutes 50-55
            Alert('same_rule_name', {'key': 'A'}, set(),
                  created=datetime(year=2000, month=1, day=1, minute=50),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=5)),

            # This alert (created now) is too recent to fit in any merge group.
            Alert('same_rule_name', {'key': 'A'}, set(),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=10))
        ]

        groups = main.AlertMerger._merge_groups(alerts)
        assert 4 == len(groups)
        assert alerts[:2] == groups[0].alerts
        assert alerts[2:5] == groups[1].alerts
        assert alerts[5:7] == groups[2].alerts
        assert [alerts[7]] == groups[3].alerts

    @patch.object(main.AlertMergeGroup, 'MAX_ALERTS_PER_GROUP', 2)
    def test_merge_groups_limit_reached(self):
        """Alert Merger - Alert Collection - Max Alerts Per Group"""
        alerts = [
            Alert('same_rule_name', {'key': 'A'}, set(),
                  created=datetime(year=2000, month=1, day=1),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=5)),
        ] * 5

        # Since max alerts per group is 2, it should create 3 merged groups.
        groups = main.AlertMerger._merge_groups(alerts)
        assert 3 == len(groups)
        assert alerts[:2] == groups[0].alerts
        assert alerts[2:4] == groups[1].alerts
        assert alerts[4:] == groups[2].alerts

    @patch.object(main, 'LOGGER')
    @patch.object(main.AlertMerger, 'MAX_LAMBDA_PAYLOAD_SIZE', 600)
    def test_dispatch(self, mock_logger):
        """Alert Merger - Dispatch to Alert Processor Lambda"""
        self.merger.lambda_client = MagicMock()

        self.merger.table.add_alerts([
            # An alert without any merge criteria
            Alert('no_merging', {}, {'output'}),

            # 2 Alerts which will be merged (and will be be too large to send the entire record)
            Alert('merge_me', {'key': True}, {'output'},
                  created=datetime(year=2000, month=1, day=1),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=5)),
            Alert('merge_me', {'key': True, 'other': 'abc' * 50}, {'output'},
                  created=datetime(year=2000, month=1, day=1, minute=1),
                  merge_by_keys=['key'], merge_window=timedelta(minutes=5)),

            # Alert which has already sent successfully (will be deleted)
            Alert('already_sent', {}, {'output'}, outputs_sent={'output'})
        ])

        self.merger.dispatch()
        # NOTE (Bobby): The following assertion was modified during the py2 -> py3
        # conversion to disregard order of calls.
        mock_logger.assert_has_calls([
            call.info('Merged %d alerts into a new alert with ID %s', 2, ANY),
            call.info('Dispatching %s to %s (attempt %d)', ANY, _ALERT_PROCESSOR, 1),
            call.info('Dispatching %s to %s (attempt %d)', ANY, _ALERT_PROCESSOR, 1)
        ], any_order=True)

    @patch.object(main, 'LOGGER')
    def test_dispatch_no_alerts(self, mock_logger):
        """Alert Merger - All Alerts Have Already Been Dispatched"""
        with patch.object(self.merger.table, 'rule_names_generator',
                          return_value=iter(['rule_name'])):
            self.merger.dispatch()
            mock_logger.assert_not_called()


@patch.object(main, 'AlertMerger')
def test_handler(mock_instance):
    """Alert Merger - Handler (Entry Point)"""
    main.handler(None, None)
    mock_instance.assert_has_calls([
        call.get_instance(),
        call.get_instance().dispatch()
    ])

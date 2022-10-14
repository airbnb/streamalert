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
from io import StringIO
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError
from moto import mock_dynamodb

from streamalert.shared import rule as rule_module
from streamalert.shared import rule_table
from tests.unit.helpers.aws_mocks import setup_mock_rules_table

_RULES_TABLE = 'PREFIX_streamalert_rules'


class TestRuleTable:
    """Tests for shared/rule_table.py"""
    # pylint: disable=protected-access

    @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    def setup(self):
        """Rule Table - Create mock table and rules"""
        # pylint: disable=attribute-defined-outside-init
        self.dynamo_mock = mock_dynamodb()
        self.dynamo_mock.start()
        setup_mock_rules_table(_RULES_TABLE)
        self.rule_table = rule_table.RuleTable(_RULES_TABLE)

    def teardown(self):
        """Rule Table - Destroy previously created rules"""
        rule_module.Rule._rules.clear()
        self.dynamo_mock.stop()

    @classmethod
    def _create_local_rules(cls, count=5):
        """Helper to create N fake local rules"""
        for i in range(count):
            cls._create_local_rule_with_name('fake_rule_{:02d}'.format(i))

    @staticmethod
    def _create_local_rule_with_name(name):
        """Helper to create a fake local rule with specified name"""
        rule_module.Rule(Mock(__name__=name), logs=['fake_log_type'])

    def _create_db_rule_with_name(self, name, stage=False):
        """Helper to create a fake database rule with specified name"""
        self.rule_table._table.put_item(Item={'RuleName': name, 'Staged': stage})

    def test_rule_table_name(self):
        """Rule Table - Table Name"""
        assert self.rule_table.name == _RULES_TABLE

    def test_local_rule_names(self):
        """Rule Table - Local Rule Names"""
        expected_result = {'test_rule_01', 'test_rule_02', 'test_rule_03'}
        for rule_name in expected_result:
            self._create_local_rule_with_name(rule_name)

        assert self.rule_table.local_rule_names == expected_result

    def test_remote_rule_names(self):
        """Rule Table - Remote Rule Names"""
        expected_result = {'remote_rule_01', 'remote_rule_02', 'remote_rule_03'}
        for rule_name in expected_result:
            self._create_db_rule_with_name(rule_name)

        assert self.rule_table.remote_rule_names == expected_result

    def test_remote_rule_info(self):
        """Rule Table - Remote Rule Info"""
        expected_result = {
            'test_rule_01': {'Staged': False},
            'test_rule_02': {'Staged': False},
            'test_rule_03': {'Staged': False}
        }
        for rule_name in expected_result:
            self._create_db_rule_with_name(rule_name)

        assert self.rule_table.remote_rule_info == expected_result

    def test_local_not_remote_names(self):
        """Rule Table - Local and Not Remote Rule Names"""
        for rule_name in {'remote_rule_01', 'remote_rule_02'}:
            self._create_db_rule_with_name(rule_name)

        expected_result = {'test_rule_01', 'test_rule_02'}
        for rule_name in expected_result:
            self._create_local_rule_with_name(rule_name)

        assert self.rule_table.local_not_remote == expected_result

    def test_remote_not_local_names(self):
        """Rule Table - Remote and Not Local Rule Names"""
        for rule_name in {'test_rule_01', 'test_rule_02'}:
            self._create_local_rule_with_name(rule_name)

        expected_result = {'remote_rule_01', 'remote_rule_02'}
        for rule_name in expected_result:
            self._create_db_rule_with_name(rule_name)

        assert self.rule_table.remote_not_local == expected_result

    def test_add_new_rules(self):
        """Rule Table - Add New Rules"""
        self._create_local_rules(2)
        self.rule_table._add_new_rules()
        assert self.rule_table._table.item_count == 2

    def test_delete_old_rules(self):
        """Rule Table - Delete New Rules"""
        # Create 2 local rules and add them to the table
        original_count = 2
        self._create_local_rules(original_count)
        self.rule_table._add_new_rules()

        # Delete a local rule from the tracking dictionary
        del rule_module.Rule._rules['fake_rule_01']

        # Ensure the remote state is updated for the deletion of a rule
        self.rule_table._del_old_rules()
        assert len(self.rule_table._load_remote_state()) == original_count - 1

    def test_load_remote_state_init(self):
        """Rule Table - Load Remote State of Rules, New Database"""
        # Create 2 local rules and add them to the table
        self._create_local_rules(2)
        self.rule_table._add_new_rules()

        expected_state = {
            'fake_rule_00': {'Staged': False},
            'fake_rule_01': {'Staged': False}
        }

        state = self.rule_table._load_remote_state()
        assert state == expected_state

    @patch('streamalert.shared.rule_table.RuleTable._staged_window')
    def test_load_remote_state_state(self, window_mock):
        """Rule Table - Load Remote State of Rules, Existing Database"""
        window_mock.return_value = ('2018-04-21T02:23:13.0Z', '2018-04-23T02:23:13.0Z')
        # Create 2 local rules and add them to the currently empty
        self._create_local_rules(2)
        self.rule_table._add_new_rules()

        # window_mock.return_value = ('start-staged-date', 'end-staged-date')
        # Create 2 local rules and add them to the currently empty
        self._create_local_rule_with_name('now_staged_rule')
        self.rule_table._add_new_rules()

        expected_state = {
            'fake_rule_00': {'Staged': False},
            'fake_rule_01': {'Staged': False},
            'now_staged_rule': {
                'Staged': True,
                'StagedAt': datetime(year=2018, month=4, day=21, hour=2, minute=23, second=13),
                'StagedUntil': datetime(year=2018, month=4, day=23, hour=2, minute=23, second=13)
            }
        }

        state = self.rule_table._load_remote_state()
        assert state == expected_state

    def test_dynamo_record_init(self):
        """Rule Table - DynamoDB Record, New Database"""
        expected_record = {
            'RuleName': 'foo_rule',
            'Staged': False
        }

        record = self.rule_table._dynamo_record('foo_rule', True)
        assert record == expected_record

    @patch('streamalert.shared.rule_table.RuleTable._staged_window')
    def test_dynamo_record(self, window_mock):
        """Rule Table - DynamoDB Record, Existing Database"""
        window_mock.return_value = ('staged-at-date', 'staged-until-date')
        expected_record = {
            'RuleName': 'foo_rule',
            'Staged': True,
            'StagedAt': 'staged-at-date',
            'StagedUntil': 'staged-until-date'
        }

        record = self.rule_table._dynamo_record('foo_rule', False)
        assert record == expected_record

    def test_get_rule_info(self):
        """Rule Table - Get Rule Info"""
        rule_name = 'test_rule_01'
        self._create_db_rule_with_name(rule_name, True)

        expected_result = {'Staged': True}
        assert self.rule_table.rule_info(rule_name) == expected_result

    @patch('streamalert.shared.rule_table.datetime')
    def test_staged_window(self, date_mock):
        """Rule Table - Staged Window"""
        date_mock.utcnow.return_value = datetime(
            year=2001, month=1, day=1, hour=12, minute=0, second=10, microsecond=123456)

        staged_at, staged_until = self.rule_table._staged_window()
        assert staged_at == '2001-01-01T12:00:10.123456Z'
        assert staged_until == '2001-01-03T12:00:10.123456Z'

    def test_update(self):
        """Rule Table - Update"""
        rule_name = 'init_rule'
        self._create_db_rule_with_name(rule_name)
        assert self.rule_table._table.item_count == 1
        self._create_local_rule_with_name('test_rule_01')
        self._create_local_rule_with_name('test_rule_02')

        # Run the update to ensure the old rule was deleted and the new rules are added
        self.rule_table.update()
        assert len(self.rule_table._load_remote_state()) == 2
        item = self.rule_table._table.get_item(Key={'RuleName': rule_name})
        assert item.get('Item') is None
        item = self.rule_table._table.get_item(Key={'RuleName': 'test_rule_02'})
        assert item['Item']['RuleName'] == 'test_rule_02'

    def test_toggle_staged_state_true(self):
        """Rule Table - Toggle Staging, Staged=True"""
        rule_name = 'unstaged_rule'
        self._create_db_rule_with_name(rule_name)

        # Make sure the item that was added is not staged
        item = self.rule_table._table.get_item(Key={'RuleName': rule_name})
        assert item['Item']['Staged'] == False

        # Try to toggle the state to staged
        self.rule_table.toggle_staged_state(rule_name, True)

        # Make sure the item is now staged
        item = self.rule_table._table.get_item(Key={'RuleName': rule_name})
        assert item['Item']['Staged']

    def test_toggle_staged_state_false(self):
        """Rule Table - Toggle Staging, Staged=False"""
        rule_name = 'staged_rule'
        self._create_db_rule_with_name(rule_name, True)

        # Make sure the item that was added is staged
        item = self.rule_table._table.get_item(Key={'RuleName': rule_name})
        assert item['Item']['Staged']

        # Try to toggle the state to unstaged
        self.rule_table.toggle_staged_state(rule_name, False)

        # Make sure the item is now unstaged
        item = self.rule_table._table.get_item(Key={'RuleName': rule_name})
        assert item['Item']['Staged'] == False

    @patch('logging.Logger.error')
    def test_toggle_staged_state_nonexistent(self, log_mock):
        """Rule Table - Toggle Staging, Nonexistent Rule"""
        rule_name = 'bad_rule'

        # Try to toggle the state of the non-existent rule to staged
        self.rule_table.toggle_staged_state(rule_name, True)
        log_mock.assert_called_with(
            'Staging status for rule \'%s\' cannot be set to %s; rule does not exist',
            rule_name,
            True
        )

    @patch('logging.Logger.info')
    def test_toggle_staged_state_update(self, log_mock):
        """Rule Table - Toggle Staging, Already Staged (Update Window)"""
        rule_name = 'staged_rule'
        staged = True
        self.rule_table._table.put_item(Item={
            'RuleName': rule_name,
            'Staged': staged,
            'StagedAt': '2018-01-01T01:01:01.000Z'
        })

        # Make sure the item that was added is staged
        orig_item = self.rule_table._table.get_item(Key={'RuleName': rule_name})
        assert orig_item['Item']['Staged'] == staged

        # Try to toggle the state of the already staged rule to staged
        # This should implicitly update the staging window
        self.rule_table.toggle_staged_state(rule_name, staged)
        log_mock.assert_called_with(
            'Rule \'%s\' is already staged and will have its staging window updated',
            rule_name
        )

        # Make sure the item is still staged
        new_item = self.rule_table._table.get_item(Key={'RuleName': rule_name})
        assert new_item['Item']['Staged']
        assert orig_item['Item']['StagedAt'] != new_item['Item']['StagedAt']

    def test_toggle_staged_state_error(self):
        """Rule Table - Toggle Staging, ClientError Occurred"""
        rule_name = 'test_rule'
        self._create_db_rule_with_name(rule_name, True)
        with patch.object(self.rule_table._table, 'update_item',
                          side_effect=ClientError({'Error': {'Code': 'TEST'}}, 'UpdateItem')):
            pytest.raises(ClientError, self.rule_table.toggle_staged_state, rule_name, True)

    def test_print_table(self):
        """Rule Table - Print Table"""
        self._create_db_rule_with_name('test_01')
        self.rule_table._table.put_item(Item={
            'RuleName': 'test_02',
            'Staged': True,
            'StagedAt': '2018-04-21T02:23:13.0Z',
            'StagedUntil': '2018-04-23T02:23:13.0Z'
        })
        with patch('sys.stdout', new=StringIO()) as stdout:
            print(self.rule_table)
            expected_output = """
Rule            Staged?
  1: test_01    False
  2: test_02    True
"""

            output = stdout.getvalue().strip()
            assert output == expected_output.strip()

    def test_print_table_empty(self):
        """Rule Table - Print Table, Empty"""
        with patch('sys.stdout', new=StringIO()) as stdout:
            print(self.rule_table)
            expected_output = 'Rule table is empty'
            output = stdout.getvalue().strip()
            assert output == expected_output.strip()

    def test_print_table_verbose(self):
        """Rule Table - Print Table, Verbose"""
        self._create_db_rule_with_name('test_01')
        self.rule_table._table.put_item(Item={
            'RuleName': 'test_02',
            'Staged': True,
            'StagedAt': '2018-04-21T02:23:13.0Z',
            'StagedUntil': '2018-04-23T02:23:13.0Z'
        })
        with patch('sys.stdout', new=StringIO()) as stdout:
            print(self.rule_table.__str__(True))
            expected_output = """
Rule            Staged?
  1: test_01    False
  2: test_02    True
     - StagedAt:      2018-04-21 02:23:13
     - StagedUntil:   2018-04-23 02:23:13
"""

            output = stdout.getvalue().strip()
            assert output == expected_output.strip()

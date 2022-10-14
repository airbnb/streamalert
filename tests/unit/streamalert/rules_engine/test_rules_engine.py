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
# pylint: disable=invalid-name

from datetime import datetime, timedelta
from unittest.mock import Mock, PropertyMock, patch

import streamalert.rules_engine.rules_engine as rules_engine_module
from publishers.community.generic import remove_internal_fields
from streamalert.rules_engine.rules_engine import RulesEngine
from streamalert.shared.publisher import (AlertPublisher, DefaultPublisher,
                                          Register)


def mock_conf():
    return {
        'global': {
            'general': {
                'rule_locations': [],
                'matcher_locations': []
            },
            'infrastructure': {
                'rule_staging': {
                    'enabled': True
                }
            }
        }
    }


@Register
def that_publisher(_, __):
    return {}


@Register
class ThisPublisher(AlertPublisher):
    def publish(self, alert, publication):
        return {}


# Without this time.sleep patch, backoff performs sleep
# operations and drastically slows down testing
# @patch('time.sleep', Mock())
# pylint: disable=R0904
class TestRulesEngine:
    """Tests for RulesEngine"""
    # pylint: disable=attribute-defined-outside-init,protected-access,no-self-use

    def setup(self):
        """RulesEngine - Setup"""
        with patch.object(rules_engine_module, 'Alert'), \
            patch.object(rules_engine_module, 'AlertForwarder'), \
            patch.object(rules_engine_module, 'RuleTable'), \
            patch.object(rules_engine_module, 'ThreatIntel'), \
            patch.dict('os.environ', {'STREAMALERT_PREFIX': 'test_prefix'}), \
            patch('streamalert.rules_engine.rules_engine.load_config',
                  Mock(return_value=mock_conf())):
            self._rules_engine = RulesEngine()

    def teardown(self):
        """RulesEngine - Teardown"""
        RulesEngine._config = None
        RulesEngine._lookup_tables = None
        RulesEngine._rule_table = None
        RulesEngine._threat_intel = None
        RulesEngine._alert_forwarder = None
        RulesEngine._RULE_TABLE_LAST_REFRESH = datetime(year=1970, month=1, day=1)

    def test_load_rule_table_disabled(self):
        """RulesEngine - Load Rule Table, Disabled"""
        RulesEngine._rule_table = None
        RulesEngine._RULE_TABLE_LAST_REFRESH = datetime(year=1970, month=1, day=1)
        config = mock_conf()
        config['global']['infrastructure']['rule_staging']['enabled'] = False
        RulesEngine._load_rule_table(config)
        assert RulesEngine._rule_table is None
        assert RulesEngine._RULE_TABLE_LAST_REFRESH == datetime(year=1970, month=1, day=1)

    @patch('logging.Logger.debug')
    def test_load_rule_table_no_refresh(self, log_mock):
        """RulesEngine - Load Rule Table, No Refresh"""
        config = mock_conf()
        RulesEngine._RULE_TABLE_LAST_REFRESH = datetime.utcnow()
        RulesEngine._rule_table = 'table'
        self._rules_engine._load_rule_table(config)
        assert self._rules_engine._rule_table == 'table'
        log_mock.assert_called()

    @patch.dict('os.environ', {'STREAMALERT_PREFIX': 'test_prefix'})
    @patch('logging.Logger.info')
    def test_load_rule_table_refresh(self, log_mock):
        """RulesEngine - Load Rule Table, Refresh"""
        config = mock_conf()
        config['global']['infrastructure']['rule_staging']['cache_refresh_minutes'] = 5

        fake_date_now = datetime.utcnow()

        RulesEngine._RULE_TABLE_LAST_REFRESH = fake_date_now - timedelta(minutes=6)
        RulesEngine._rule_table = 'table'
        with patch('streamalert.rules_engine.rules_engine.datetime') as date_mock, patch.object(rules_engine_module, 'RuleTable') as rule_table_mock:

            rule_table_mock.return_value = 'new_table'
            date_mock.utcnow.return_value = fake_date_now
            self._rules_engine._load_rule_table(config)
            assert self._rules_engine._rule_table == 'new_table'
            assert self._rules_engine._RULE_TABLE_LAST_REFRESH == fake_date_now
            log_mock.assert_called()

    def test_process_subkeys_none(self):
        """RulesEngine - Process Subkeys, None Defined"""
        rule = Mock(
            req_subkeys=None
        )

        assert RulesEngine._process_subkeys(None, rule)

    def test_process_subkeys_missing_key(self):
        """RulesEngine - Process Subkeys, Missing Key"""
        rule = Mock(
            req_subkeys={'data': ['location']},
            name='test_rule'
        )

        record = {
            'host': 'host1.web.prod.net'
        }

        result = RulesEngine._process_subkeys(record, rule)
        assert result == False

    def test_process_subkeys_bad_type(self):
        """RulesEngine - Process Subkeys, Bad Subtype"""
        rule = Mock(
            req_subkeys={'data': ['location']},
            name='test_rule'
        )

        record = {
            'host': 'host1.web.prod.net',
            'data': 'value'
        }

        result = RulesEngine._process_subkeys(record, rule)
        assert result == False

    def test_process_subkeys_missing_subkey(self):
        """RulesEngine - Process Subkeys, Missing Subkey"""
        rule = Mock(
            req_subkeys={'data': ['location']},
            name='test_rule'
        )

        record = {
            'host': 'host1.web.prod.net',
            'data': {
                'category': 'web-server'
            }
        }

        result = RulesEngine._process_subkeys(record, rule)
        assert result == False

    def test_process_subkeys(self):
        """RulesEngine - Process Subkeys"""
        rule = Mock(
            req_subkeys={'data': ['location']},
            name='test_rule'
        )

        record = {
            'host': 'host1.web.prod.net',
            'data': {
                'location': 'us-west-2'
            }
        }

        result = RulesEngine._process_subkeys(record, rule)
        assert result

    # -- Tests for _rule_analysis()

    def test_rule_analysis(self):
        """RulesEngine - Rule Analysis"""
        rule = Mock(
            process=Mock(return_value=True),
            is_staged=Mock(return_value=False),
            outputs_set={'slack:test'},
            dynamic_outputs=None,
            description='rule description',
            publishers=None,
            context=None,
            merge_by_keys=None,
            merge_window_mins=0
        )

        # Override the Mock name attribute
        type(rule).name = PropertyMock(return_value='test_rule')
        record = {'foo': 'bar'}
        payload = {
            'cluster': 'prod',
            'log_schema_type': 'log_type',
            'data_type': 'json',
            'resource': 'test_stream',
            'service': 'kinesis',
            'record': record
        }

        with patch.object(rules_engine_module, 'Alert') as alert_mock:
            result = self._rules_engine._rule_analysis(payload, rule)
            alert_mock.assert_called_with(
                'test_rule', record, {'aws-firehose:alerts', 'slack:test'},
                cluster='prod',
                context=None,
                log_source='log_type',
                log_type='json',
                merge_by_keys=None,
                merge_window=timedelta(minutes=0),
                publishers=None,
                rule_description='rule description',
                source_entity='test_stream',
                source_service='kinesis',
                staged=False
            )

            assert result is not None

    def test_rule_analysis_staged(self):
        """RulesEngine - Rule Analysis, Staged"""
        rule = Mock(
            process=Mock(return_value=True),
            is_staged=Mock(return_value=True),
            outputs_set={'slack:test'},
            description='rule description',
            publishers=None,
            context=None,
            merge_by_keys=None,
            merge_window_mins=0
        )

        # Override the Mock name attribute
        type(rule).name = PropertyMock(return_value='test_rule')
        record = {'foo': 'bar'}
        payload = {
            'cluster': 'prod',
            'log_schema_type': 'log_type',
            'data_type': 'json',
            'resource': 'test_stream',
            'service': 'kinesis',
            'record': record
        }

        with patch.object(rules_engine_module, 'Alert') as alert_mock:
            result = self._rules_engine._rule_analysis(payload, rule)
            alert_mock.assert_called_with(
                'test_rule', record, {'aws-firehose:alerts'},
                cluster='prod',
                context=None,
                log_source='log_type',
                log_type='json',
                merge_by_keys=None,
                merge_window=timedelta(minutes=0),
                publishers=None,
                rule_description='rule description',
                source_entity='test_stream',
                source_service='kinesis',
                staged=True
            )

            assert result is not None

    def test_rule_analysis_false(self):
        """RulesEngine - Rule Analysis, False"""
        rule = Mock(
            process=Mock(return_value=False),
        )
        result = self._rules_engine._rule_analysis({'record': {'foo': 'bar'}}, rule)
        assert result is None

    def test_rule_analysis_with_publishers(self):
        """RulesEngine - Rule Analysis, Publishers"""
        rule = Mock(
            process=Mock(return_value=True),
            is_staged=Mock(return_value=False),
            outputs_set={'slack:test', 'demisto:test'},
            dynamic_outputs=None,
            description='rule description',
            publishers={
                'demisto': 'streamalert.shared.publisher.DefaultPublisher',
                'slack': [that_publisher],
                'slack:test': [ThisPublisher],
            },
            context=None,
            merge_by_keys=None,
            merge_window_mins=0
        )

        # Override the Mock name attribute
        type(rule).name = PropertyMock(return_value='test_rule')
        record = {'foo': 'bar'}
        payload = {
            'cluster': 'prod',
            'log_schema_type': 'log_type',
            'data_type': 'json',
            'resource': 'test_stream',
            'service': 'kinesis',
            'record': record
        }

        with patch.object(rules_engine_module, 'Alert') as alert_mock:
            result = self._rules_engine._rule_analysis(payload, rule)
            alert_mock.assert_called_with(
                'test_rule', record, {'aws-firehose:alerts', 'slack:test', 'demisto:test'},
                cluster='prod',
                context=None,
                log_source='log_type',
                log_type='json',
                merge_by_keys=None,
                merge_window=timedelta(minutes=0),
                publishers={
                    'slack:test': [
                        'tests.unit.streamalert.rules_engine.test_rules_engine.that_publisher',
                        'tests.unit.streamalert.rules_engine.test_rules_engine.ThisPublisher',
                    ],
                    'demisto:test': [
                        'streamalert.shared.publisher.DefaultPublisher'
                    ],
                },
                rule_description='rule description',
                source_entity='test_stream',
                source_service='kinesis',
                staged=False
            )

            assert result is not None

    # --- Tests for _configure_outputs()

    def test_check_valid_output_list(self):
        """RulesEngine - _check_valid_output, list"""

        output = []
        result = self._rules_engine._check_valid_output(output)

        assert not result

    def test_check_valid_output_int(self):
        """RulesEngine - _check_valid_output, int"""

        output = 1
        result = self._rules_engine._check_valid_output(output)

        assert not result

    def test_check_valid_output_invalid_string(self):
        """RulesEngine - _check_valid_output, invalid string"""

        output = "aws-sns"  # missing :
        result = self._rules_engine._check_valid_output(output)

        assert not result

    def test_check_valid_output_valid_string(self):
        """RulesEngine - _check_valid_output, valid string"""

        output = "aws-sns:test"
        result = self._rules_engine._check_valid_output(output)

        assert result

    @patch('logging.Logger.error')
    def test_call_dynamic_output_function_raise_error(self, log_error):
        """RulesEngine - _call_dynamic_output_function, raise error"""
        dynamic_output_function = Mock(__name__='test', side_effect=Exception('BOOM!'))

        rule_name = "test"

        dynamic_outputs = self._rules_engine._call_dynamic_output_function(
            dynamic_output_function, rule_name, []
        )

        assert dynamic_outputs == []
        log_error.assert_called_with(
            'Exception when calling dynamic_output %s for rule %s', 'test', rule_name
        )

    def test_call_dynamic_output_function_string(self):
        """RulesEngine - _call_dynamic_output_function, output returns string"""
        dynamic_output_function = Mock(__name__='test', return_value="test")

        record = {'foo': 'bar'}
        dynamic_outputs = self._rules_engine._call_dynamic_output_function(
            dynamic_output_function, "test", [record]
        )

        assert dynamic_outputs == ["test"]
        dynamic_output_function.assert_called()
        dynamic_output_function.assert_called_with(record)

    def test_call_dynamic_output_function_list(self):
        """RulesEngine - _call_dynamic_output_function, output returns list"""
        dynamic_output_function = Mock(__name__='test', return_value=["test"])

        record = {'foo': 'bar'}
        dynamic_outputs = self._rules_engine._call_dynamic_output_function(
            dynamic_output_function, "test", [record]
        )

        assert dynamic_outputs == ["test"]
        dynamic_output_function.assert_called()
        dynamic_output_function.assert_called_with(record)

    def test_call_dynamic_output_function_none(self):
        """RulesEngine - _call_dynamic_output_function, output returns None"""
        dynamic_output_function = Mock(__name__='test', return_value=None)

        record = {'foo': 'bar'}
        dynamic_outputs = self._rules_engine._call_dynamic_output_function(
            dynamic_output_function, "test", [record]
        )

        assert dynamic_outputs == []
        dynamic_output_function.assert_called()
        dynamic_output_function.assert_called_with(record)

    def test_configure_dynamic_outputs_no_context(self):
        """RulesEngine - _configure_dynamic_outputs, no context"""
        dynamic_output = Mock(return_value="aws-sns:test")
        rule = Mock(
            name="test",
            outputs_set=set(),
            dynamic_outputs_set={dynamic_output},
            publishers=None,
            context=None,
        )
        record = {'foo': 'bar'}

        with patch.object(RulesEngine, "_call_dynamic_output_function") as call_dynamic:
            call_dynamic.return_value = ["aws-sns:test"]

            dynamic_outputs = self._rules_engine._configure_dynamic_outputs(record, rule)

            # Tests
            assert dynamic_outputs == ["aws-sns:test"]
            call_dynamic.assert_called()
            call_dynamic.assert_called_with(dynamic_output, rule.name, [record])

    def test_configure_dynamic_outputs_with_context(self):
        """RulesEngine - _configure_dynamic_outputs, with context"""
        dynamic_output = Mock(return_value="aws-sns:test")
        rule = Mock(
            name="test",
            outputs_set=set(),
            dynamic_outputs_set={dynamic_output},
            publishers=None,
            context={"test": True},
        )
        record = {'foo': 'bar'}

        with patch.object(RulesEngine, "_call_dynamic_output_function") as call_dynamic:
            call_dynamic.return_value = ["aws-sns:test"]

            dynamic_outputs = self._rules_engine._configure_dynamic_outputs(record, rule)

            # Tests
            assert dynamic_outputs == ["aws-sns:test"]
            call_dynamic.assert_called()
            call_dynamic.assert_called_with(dynamic_output, rule.name, [record, rule.context])

    def test_configure_dynamic_outputs_empty_list(self):
        """RulesEngine - _configure_dynamic_outputs, empty list"""
        dynamic_output = Mock(return_value=None)
        rule = Mock(
            name="test",
            outputs_set=set(),
            dynamic_outputs_set={dynamic_output},
            publishers=None,
            context=None,
        )
        record = {'foo': 'bar'}

        with patch.object(RulesEngine, "_call_dynamic_output_function") as call_dynamic:
            call_dynamic.return_value = []

            dynamic_outputs = self._rules_engine._configure_dynamic_outputs(record, rule)

            # Tests
            assert dynamic_outputs == []
            call_dynamic.assert_called()
            call_dynamic.assert_called_with(dynamic_output, rule.name, [record])

    def test_configure_outputs_staged(self):
        """RulesEngine - _configure_outputs, staged rule"""
        rule = Mock(
            outputs_set=set(),
            is_staged=Mock(return_value=True),
        )
        record = {'foo': 'bar'}

        with patch.object(RulesEngine, "_check_valid_output") as check_valid:
            check_valid.return_value = True

            outputs = self._rules_engine._configure_outputs(record, rule)

            # Tests
            rule.is_staged.assert_called()
            check_valid.assert_called()
            assert outputs == self._rules_engine._required_outputs_set

    def test_configure_outputs_unstaged_with_static_outputs(self):
        """RulesEngine - _configure_outputs, unstaged with static outputs"""
        rule = Mock(
            outputs_set={"aws-sns:static"},
            dynamic_outputs=None,
            is_staged=Mock(return_value=False),
        )
        record = {'foo': 'bar'}

        with patch.object(RulesEngine, "_check_valid_output") as check_valid:
            check_valid.return_value = True

            outputs = self._rules_engine._configure_outputs(record, rule)

            # Tests
            rule.is_staged.assert_called()
            check_valid.assert_called()
            expected = self._rules_engine._required_outputs_set.union({"aws-sns:static"})
            assert outputs == expected

    def test_configure_outputs_unstaged_with_no_outputs(self):
        """RulesEngine - _configure_outputs, unstaged with no additional outputs"""
        rule = Mock(
            outputs_set=set(),
            dynamic_outputs=None,
            is_staged=Mock(return_value=False),
        )
        record = {'foo': 'bar'}

        with patch.object(RulesEngine, "_check_valid_output") as check_valid:
            check_valid.return_value = True

            outputs = self._rules_engine._configure_outputs(record, rule)

            # Tests
            rule.is_staged.assert_called()
            assert outputs == self._rules_engine._required_outputs_set

    def test_configure_outputs_unstaged_with_dynamic_outputs(self):
        """RulesEngine - _configure_outputs, unstaged with dynamic outputs"""
        rule = Mock(
            outputs_set=set(),
            dynamic_outputs=[Mock(return_value="aws-sns:dynamic")],
            is_staged=Mock(return_value=False),
        )
        record = {'foo': 'bar'}

        with patch.object(RulesEngine, "_configure_dynamic_outputs") as configure_dynamic:
            configure_dynamic.return_value = ["aws-sns:dynamic"]

            with patch.object(RulesEngine, "_check_valid_output") as check_valid:
                check_valid.return_value = True

                outputs = self._rules_engine._configure_outputs(record, rule)

                # Tests
                rule.is_staged.assert_called()
                configure_dynamic.assert_called()
                configure_dynamic.assert_called_with(record, rule)
                check_valid.assert_called()
                expected = self._rules_engine._required_outputs_set.union({"aws-sns:dynamic"})
                assert outputs == expected

    def test_configure_outputs_unstaged_with_all_outputs(self):
        """RulesEngine - _configure_outputs, unstaged with all output sources"""
        rule = Mock(
            outputs_set={"aws-sns:static"},
            dynamic_outputs=[Mock(return_value="aws-sns:dynamic")],
            is_staged=Mock(return_value=False),
        )
        record = {'foo': 'bar'}

        with patch.object(RulesEngine, "_configure_dynamic_outputs") as configure_dynamic:
            configure_dynamic.return_value = ["aws-sns:dynamic"]

            with patch.object(RulesEngine, "_check_valid_output") as check_valid:
                check_valid.return_value = True

                outputs = self._rules_engine._configure_outputs(record, rule)

                # Tests
                rule.is_staged.assert_called()
                configure_dynamic.assert_called()
                configure_dynamic.assert_called_with(record, rule)
                check_valid.assert_called()
                expected = self._rules_engine._required_outputs_set.union(
                    {"aws-sns:static", "aws-sns:dynamic"}
                )
                assert outputs == expected

    def test_configure_outputs_invalid_output(self):
        """RulesEngine - _configure_outputs, unstaged with all outputs and one invalid output"""
        rule = Mock(
            outputs_set={"aws-sns:static"},
            dynamic_outputs=[Mock(return_value="invalid_output_will_not_be_in_final_outputs")],
            is_staged=Mock(return_value=False),
        )
        record = {'foo': 'bar'}

        with patch.object(RulesEngine, "_configure_dynamic_outputs") as configure_dynamic:
            configure_dynamic.return_value = ["invalid_output_will_not_be_in_final_outputs"]

            outputs = self._rules_engine._configure_outputs(record, rule)

            # Tests
            rule.is_staged.assert_called()
            configure_dynamic.assert_called()
            configure_dynamic.assert_called_with(record, rule)
            expected = self._rules_engine._required_outputs_set.union({"aws-sns:static"})
            assert outputs == expected

    # --- Tests for _configure_publishers()

    def test_configure_publishers_empty(self):
        """RulesEngine - _configure_publishers, Empty"""
        outputs = {'slack:test'}
        rule = Mock(
            outputs_set=outputs,
            publishers=None,
        )

        publishers = self._rules_engine._configure_publishers(rule, outputs)
        assert publishers is None

    def test_configure_publishers_single_string(self):
        """RulesEngine - _configure_publishers, Single string"""
        outputs = {'slack:test'}
        rule = Mock(
            outputs_set=outputs,
            publishers='streamalert.shared.publisher.DefaultPublisher'
        )

        publishers = self._rules_engine._configure_publishers(rule, outputs)
        expectation = {'slack:test': ['streamalert.shared.publisher.DefaultPublisher']}

        assert publishers == expectation

    def test_configure_publishers_single_reference(self):
        """RulesEngine - _configure_publishers, Single reference"""
        outputs = {'slack:test'}
        rule = Mock(
            outputs_set=outputs,
            publishers=DefaultPublisher
        )

        publishers = self._rules_engine._configure_publishers(rule, outputs)
        expectation = {'slack:test': ['streamalert.shared.publisher.DefaultPublisher']}

        assert publishers == expectation

    @patch('logging.Logger.warning')
    def test_configure_publishers_single_invalid_string(self, log_warn):
        """RulesEngine - _configure_publishers, Invalid string"""
        outputs = {'slack:test'}
        rule = Mock(
            outputs_set=outputs,
            publishers='blah'
        )

        publishers = self._rules_engine._configure_publishers(rule, outputs)
        expectation = {'slack:test': []}

        assert publishers == expectation
        log_warn.assert_called_with('Requested publisher named (%s) is not registered.', 'blah')

    @patch('logging.Logger.error')
    def test_configure_publishers_single_invalid_object(self, log_error):
        """RulesEngine - _configure_publishers, Invalid object"""
        outputs = {'slack:test'}
        rule = Mock(
            outputs_set=outputs,
            publishers=self  # just some random object that's not a publisher
        )

        publishers = self._rules_engine._configure_publishers(rule, outputs)
        expectation = {'slack:test': []}

        assert publishers == expectation
        log_error.assert_called_with('Invalid publisher argument: %s', self)

    def test_configure_publishers_single_applies_to_multiple_outputs(self):
        """RulesEngine - _configure_publishers, Multiple outputs"""
        outputs = {'slack:test', 'demisto:test', 'pagerduty:test'}
        rule = Mock(
            outputs_set=outputs,
            publishers=DefaultPublisher
        )

        publishers = self._rules_engine._configure_publishers(rule, outputs)
        expectation = {
            'slack:test': ['streamalert.shared.publisher.DefaultPublisher'],
            'demisto:test': ['streamalert.shared.publisher.DefaultPublisher'],
            'pagerduty:test': ['streamalert.shared.publisher.DefaultPublisher'],
        }

        assert publishers == expectation

    def test_configure_publishers_list(self):
        """RulesEngine - _configure_publishers, List"""
        outputs = {'slack:test'}
        rule = Mock(
            outputs_set=outputs,
            publishers=[DefaultPublisher, remove_internal_fields]
        )

        publishers = self._rules_engine._configure_publishers(rule, outputs)
        expectation = {'slack:test': [
            'streamalert.shared.publisher.DefaultPublisher',
            'publishers.community.generic.remove_internal_fields',
        ]}

        assert publishers == expectation

    def test_configure_publishers_mixed_list(self):
        """RulesEngine - _configure_publishers, Mixed List"""
        outputs = {'slack:test', 'demisto:test'}
        rule = Mock(
            outputs_set=outputs,
            publishers={
                'demisto': 'streamalert.shared.publisher.DefaultPublisher',
                'slack': [that_publisher],
                'slack:test': [ThisPublisher],
            },
        )

        publishers = self._rules_engine._configure_publishers(rule, outputs)
        expectation = {
            'slack:test': [
                'tests.unit.streamalert.rules_engine.test_rules_engine.that_publisher',
                'tests.unit.streamalert.rules_engine.test_rules_engine.ThisPublisher'
            ],
            'demisto:test': ['streamalert.shared.publisher.DefaultPublisher']
        }

        assert publishers == expectation

    def test_configure_publishers_mixed_single(self):
        """RulesEngine - _configure_publishers, Mixed Single"""
        outputs = {'slack:test', 'demisto:test'}
        rule = Mock(
            outputs_set=outputs,
            publishers={
                'demisto': 'streamalert.shared.publisher.DefaultPublisher',
                'slack': that_publisher,
                'slack:test': ThisPublisher,
            },
        )

        publishers = self._rules_engine._configure_publishers(rule, outputs)
        expectation = {
            'slack:test': [
                'tests.unit.streamalert.rules_engine.test_rules_engine.that_publisher',
                'tests.unit.streamalert.rules_engine.test_rules_engine.ThisPublisher',
            ],
            'demisto:test': ['streamalert.shared.publisher.DefaultPublisher']
        }

        assert publishers == expectation

    def test_run_subkey_failure(self):
        """RulesEngine - Run, Fail Subkey Check"""
        self._rules_engine._threat_intel = None
        with patch.object(self._rules_engine, '_process_subkeys') as subkey_mock, \
                patch.object(self._rules_engine, '_alert_forwarder'), \
                patch.object(self._rules_engine, '_rule_analysis') as analysis_mock:

            subkey_mock.return_value = False

            records = [
                {
                    'record': {
                        'key_01': 'value_01'
                    },
                    'log_schema_type': 'log_type'
                }
            ]

            self._rules_engine.run(records)
            analysis_mock.assert_not_called()

    def test_run_matcher_failure(self):
        """RulesEngine - Run, Matcher Failure"""
        self._rules_engine._threat_intel = None
        with patch.object(self._rules_engine, '_process_subkeys'), \
                patch.object(self._rules_engine, '_alert_forwarder'), \
                patch.object(self._rules_engine, '_rule_analysis') as analysis_mock:

            records = [
                {
                    'record': {
                        'key_01': 'value_01'
                    },
                    'log_schema_type': 'log_type'
                }
            ]

            self._rules_engine.run(records)
            analysis_mock.assert_not_called()

    @patch('logging.Logger.debug')
    def test_run_no_rules(self, log_mock):
        """RulesEngine - Run, No Rules"""
        self._rules_engine._threat_intel = None
        with patch.object(self._rules_engine, '_alert_forwarder'), \
                patch.object(rules_engine_module, 'Rule') as rule_mock:

            rule_mock.rules_for_log_type.return_value = None

            records = [
                {
                    'record': {
                        'key_01': 'value_01'
                    },
                    'log_schema_type': 'log_type'
                }
            ]

            self._rules_engine.run(records)
            log_mock.assert_called_with('No rules to process for %s', records[0])

    def test_run(self):
        """RulesEngine - Run"""
        self._rules_engine._threat_intel = None
        with patch.object(self._rules_engine, '_process_subkeys'), \
                patch.object(self._rules_engine, '_alert_forwarder') as alert_mock, \
                patch.object(self._rules_engine, '_rule_analysis') as analysis_mock, \
                patch.object(rules_engine_module, 'Rule') as rule_mock:

            rule_mock.rules_for_log_type.return_value = [
                Mock(
                    check_matchers=Mock(return_value=True)
                )
            ]

            analysis_mock.side_effect = [True, False]

            records = [
                {
                    'record': {
                        'key_01': 'value_01'
                    },
                    'log_schema_type': 'log_type'
                },
                {
                    'record': {
                        'key_02': 'value_02'
                    },
                    'log_schema_type': 'log_type'
                }
            ]

            self._rules_engine.run(records)
            alert_mock.send_alerts.assert_called_with([True])

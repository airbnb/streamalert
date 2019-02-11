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
from datetime import datetime, timedelta

# from botocore.exceptions import ClientError, ParamValidationError
from mock import Mock, patch, PropertyMock
from nose.tools import assert_equal

import stream_alert.rules_engine.rules_engine as rules_engine_module
from stream_alert.rules_engine.rules_engine import RulesEngine


# Without this time.sleep patch, backoff performs sleep
# operations and drastically slows down testing
# @patch('time.sleep', Mock())
class TestRulesEngine(object):
    """Tests for RulesEngine"""
    # pylint: disable=attribute-defined-outside-init,protected-access,no-self-use
    def setup(self):
        """RulesEngine - Setup"""
        with patch.object(rules_engine_module, 'Alert'), \
             patch.object(rules_engine_module, 'AlertForwarder'), \
             patch.object(rules_engine_module, 'RuleTable'), \
             patch.object(rules_engine_module, 'ThreatIntel'), \
             patch.dict('os.environ', {'STREAMALERT_PREFIX': 'test_prefix'}), \
             patch('stream_alert.rules_engine.rules_engine.load_config',
                   Mock(return_value=self._mock_conf())):
            self._rules_engine = RulesEngine()

    def teardown(self):
        """RulesEngine - Teardown"""
        RulesEngine._config = None
        RulesEngine._lookup_tables = None
        RulesEngine._rule_table = None
        RulesEngine._threat_intel = None
        RulesEngine._alert_forwarder = None
        RulesEngine._RULE_TABLE_LAST_REFRESH = datetime(year=1970, month=1, day=1)

    @classmethod
    def _mock_conf(cls):
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

    def test_load_rule_table_disabled(self):
        """RulesEngine - Load Rule Table, Disabled"""
        RulesEngine._rule_table = None
        RulesEngine._RULE_TABLE_LAST_REFRESH = datetime(year=1970, month=1, day=1)
        config = self._mock_conf()
        config['global']['infrastructure']['rule_staging']['enabled'] = False
        RulesEngine._load_rule_table(config)
        assert_equal(RulesEngine._rule_table, None)
        assert_equal(RulesEngine._RULE_TABLE_LAST_REFRESH, datetime(year=1970, month=1, day=1))

    @patch('logging.Logger.debug')
    def test_load_rule_table_no_refresh(self, log_mock):
        """RulesEngine - Load Rule Table, No Refresh"""
        config = self._mock_conf()
        RulesEngine._RULE_TABLE_LAST_REFRESH = datetime.utcnow()
        RulesEngine._rule_table = 'table'
        self._rules_engine._load_rule_table(config)
        assert_equal(self._rules_engine._rule_table, 'table')
        log_mock.assert_called()

    @patch.dict('os.environ', {'STREAMALERT_PREFIX': 'test_prefix'})
    @patch('logging.Logger.info')
    def test_load_rule_table_refresh(self, log_mock):
        """RulesEngine - Load Rule Table, Refresh"""
        config = self._mock_conf()
        config['global']['infrastructure']['rule_staging']['cache_refresh_minutes'] = 5

        fake_date_now = datetime.utcnow()

        RulesEngine._RULE_TABLE_LAST_REFRESH = fake_date_now - timedelta(minutes=6)
        RulesEngine._rule_table = 'table'
        with patch('stream_alert.rules_engine.rules_engine.datetime') as date_mock, \
             patch.object(rules_engine_module, 'RuleTable') as rule_table_mock:

            rule_table_mock.return_value = 'new_table'
            date_mock.utcnow.return_value = fake_date_now
            self._rules_engine._load_rule_table(config)
            assert_equal(self._rules_engine._rule_table == 'new_table', True)
            assert_equal(self._rules_engine._RULE_TABLE_LAST_REFRESH, fake_date_now)
            log_mock.assert_called()

    def test_process_subkeys_none(self):
        """RulesEngine - Process Subkeys, None Defined"""
        rule = Mock(
            req_subkeys=None
        )

        assert_equal(RulesEngine._process_subkeys(None, rule), True)

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
        assert_equal(result, False)

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
        assert_equal(result, False)

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
        assert_equal(result, False)

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
        assert_equal(result, True)

    def test_rule_analysis(self):
        """RulesEngine - Rule Analysis"""
        rule = Mock(
            process=Mock(return_value=True),
            is_staged=Mock(return_value=False),
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

            assert_equal(result is not None, True)

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

            assert_equal(result is not None, True)

    def test_rule_analysis_false(self):
        """RulesEngine - Rule Analysis, False"""
        rule = Mock(
            process=Mock(return_value=False),
        )
        result = self._rules_engine._rule_analysis({'record': {'foo': 'bar'}}, rule)
        assert_equal(result is None, True)

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

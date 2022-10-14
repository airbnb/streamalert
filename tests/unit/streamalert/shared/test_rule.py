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
# pylint: disable=no-self-use,protected-access
import hashlib
from unittest.mock import patch

import pytest

from streamalert.shared import rule, rule_table


# Rule to be used for checksum testing
def _test_checksum(_):
    return False


# Rule with docstring to be used for checksum testing
def _test_checksum_doc(_):
    """This has a docstring but should match the checksum of the above function"""
    return False


class TestRule:
    """TestRule class"""

    def setup(self):
        rule.Rule._rules.clear()

    def teardown(self):
        rule.Rule._rules.clear()

    @staticmethod
    def _create_rule_helper(rule_name, options=None):
        """Simple helper to create a rule from a code block

        This injects rule name in to the code block and executes
        it with the passed 'options'

        Args:
            rule_name (str): Name of rule to use for rule function
            options (dict): Optional rule information, like 'logs', 'outputs', etc
        """
        if not options:
            options = {'logs': ['log_type_01']}

        custom_rule_code = """
@rule.rule(**options)
def {}(_):
    return False
""".format(rule_name)

        exec(custom_rule_code)  # nosec # pylint: disable=exec-used

    def test_rule_valid(self):
        """Rule - Create Valid Rule"""
        self._create_rule_helper('test_rule')
        assert list(rule.Rule._rules.keys()) == ['test_rule']

    @pytest.mark.xfail(raises=rule.RuleCreationError)
    def test_rule_invalid(self):
        """Rule - Create Rule, Missing Args"""
        # Rules must either have `logs` or `datatypes` defined
        self._create_rule_helper('test_rule', {'outputs': ['fake_output']})

    @pytest.mark.xfail(raises=rule.RuleCreationError)
    def test_rule_exists(self):
        """Rule - Create Rule, Rule Already Exists"""
        # Rules must either have `logs` or `datatypes` defined
        self._create_rule_helper('test_rule')
        self._create_rule_helper('test_rule')

    def test_rule_disable(self):
        """Rule - Disabled Rule"""
        @rule.disable
        @rule.rule(logs=['log_type'])
        def test_rule_disabled(_):  # pylint: disable=unused-variable
            return False

        assert rule.Rule._rules['test_rule_disabled'].disabled

    def test_rule_to_string(self):
        """Rule - String Representation"""
        def test_rule(_):
            pass
        test_rule = rule.Rule(test_rule, outputs=['foo'], logs=['bar'])
        assert str(test_rule) == '<Rule: test_rule; outputs: [\'foo\']; disabled: False>'
        assert repr(test_rule) == '<Rule: test_rule; outputs: [\'foo\']; disabled: False>'

    def test_check_matchers(self):
        """Rule - Check Matchers, True"""
        def test_matcher(rec):
            return rec['value'] == 100

        def test_rule(_):
            return False

        test_rule = rule.Rule(test_rule, logs=['bar'], matchers=[test_matcher])

        test_record = {'value': 100}

        assert test_rule.check_matchers(test_record)

    def test_check_matchers_false(self):
        """Rule - Check Matchers, False"""
        def test_matcher(rec):
            return rec['value'] == 100

        def test_rule(_):
            return True

        test_rule = rule.Rule(test_rule, logs=['bar'], matchers=[test_matcher])

        test_record = {'value': 200}

        assert test_rule.check_matchers(test_record) == False

    @patch('logging.Logger.exception')
    def test_check_matchers_exception(self, log_mock):
        """Rule - Check Matchers, Exception"""
        def test_matcher(_):
            raise ValueError('this is a bad matcher')

        def test_rule(_):
            return True

        test_rule = rule.Rule(test_rule, logs=['bar'], matchers=[test_matcher])

        assert test_rule.check_matchers(None) == False
        log_mock.assert_called_with('Encountered error with matcher: %s', 'test_matcher')

    @patch('logging.Logger.exception')
    def test_rule_process_exception(self, log_mock):
        """Rule - Process, Exception"""
        # Create a rule function that will raise an exception
        def test_rule(_):
            raise ValueError('this is a bad rule')
        test_rule = rule.Rule(test_rule, logs=['bar'])
        result = test_rule.process(None)
        log_mock.assert_called_with('Encountered error with rule: %s', 'test_rule')
        assert result == False

    def test_rule_process(self):
        """Rule - Process, Valid"""
        def test_rule(_):
            return True
        test_rule = rule.Rule(test_rule, logs=['bar'])
        result = test_rule.process(None)
        assert result

    def test_rule_process_with_context(self):
        """Rule - Process, With Context"""
        def test_rule(rec, context):  # pylint: disable=missing-docstring
            context['relevant'] = 'data'
            # Update the context with the entire record so we can check for validity
            context.update(rec)
            return True
        test_rule = rule.Rule(test_rule, logs=['bar'], context={})

        # Test with data that should be placed into the context and overwritten
        # in subsequent calls
        test_rule.process({'foo': 'bar'})
        assert test_rule.context == {'foo': 'bar', 'relevant': 'data'}

        # Test with new data that should get placed into the context
        # The previous data should no longer be present
        test_rule.process({'bar': 'foo'})
        assert test_rule.context == {'bar': 'foo', 'relevant': 'data'}

    def test_get_rule(self):
        """Rule - Get Rule"""
        rule_name = 'test_rule'
        self._create_rule_helper(rule_name)
        result = rule.Rule.get_rule(rule_name)
        assert result.name == rule_name

    def test_rule_names(self):
        """Rule - Get Rule Names"""
        rule_names = ['test_rule_01', 'test_rule_02']
        for name in rule_names:
            self._create_rule_helper(name)
        assert rule.Rule.rule_names() == rule_names

    def test_rule_checksum(self):
        """Rule - Rule Checksum"""
        # The known dumped ast of a function that just returns False is below
        ast_value = 'Return(value=Constant(value=False))'

        # The known checksum of the above is # c119f541816c6364ea3e2e884ba18f9c
        expected_checksum = hashlib.md5(ast_value.encode('utf-8')).hexdigest()  # nosec

        # Test rule without a docstring
        rule.Rule(_test_checksum, logs=['log_type'])
        assert rule.Rule._rules['_test_checksum'].checksum == expected_checksum

        # Test rule with a docstring
        rule.Rule(_test_checksum_doc, logs=['log_type'])
        assert rule.Rule._rules['_test_checksum_doc'].checksum == expected_checksum

    @patch('logging.Logger.exception')
    def test_rule_checksum_bad(self, log_mock):
        """Rule - Rule Checksum, Bad Indentation"""
        def test_rule(_):
            return False

        # Test rule that has bad indentation when loading from source
        rule.Rule(test_rule, logs=['log_type'])
        assert rule.Rule._rules['test_rule'].checksum == rule.Rule.CHECKSUM_UNKNOWN
        log_mock.assert_called_with('Could not checksum rule function')

    @patch.dict('os.environ', {'AWS_DEFAULT_REGION': 'us-east-1'})
    def test_rule_is_staged_false(self):
        """Rule - Is Staged = False"""
        table = rule_table.RuleTable('table')
        table._remote_rule_info = {'test_rule': {'Staged': False}}

        def test_rule(_):
            return True

        # Test rule is not staged
        unstaged_rule = test_rule = rule.Rule(test_rule, logs=['bar'])
        assert unstaged_rule.is_staged(None) == False
        assert unstaged_rule.is_staged(table) == False

    @patch.dict('os.environ', {'AWS_DEFAULT_REGION': 'us-east-1'})
    def test_rule_is_staged(self):
        """Rule - Is Staged = True"""
        table = rule_table.RuleTable('table')
        table._remote_rule_info = {'test_rule': {'Staged': True}}

        def test_rule(_):
            return True

        # Test rule is not staged
        staged_rule = test_rule = rule.Rule(test_rule, logs=['bar'])
        assert staged_rule.is_staged(table)

    def test_get_rules_with_datatypes(self):
        """Rule - Get Rules, Rule With Datatypes"""
        # Add a rule (this one will have no datatypes)
        self._create_rule_helper('no_datatypes')

        # Add another rule with datatypes
        self._create_rule_helper('with_datatypes', {'datatypes': ['sourceAddress']})

        result = rule.Rule.rules_with_datatypes()
        # Make sure both rules are there
        assert len(rule.Rule.rule_names()) == 2
        # Check to see if the one with datatypes is returned
        assert len(result) == 1
        assert result[0].name == 'with_datatypes'

    def test_set_description(self):
        """Rule - Set Description"""
        def test_rule(_):
            pass
        test_rule = rule.Rule(test_rule, outputs=['foo'], logs=['bar'])

        description = 'foobar description'
        test_rule.description = description

        assert test_rule.description == description

    def test_get_rules_for_log_type(self):
        """Rule - Get Rules, For Log Type"""
        self._create_rule_helper('rule_01')
        self._create_rule_helper('rule_02', {'logs': ['log_type_02']})
        self._create_rule_helper('rule_03', {'logs': ['log_type_01', 'log_type_02']})
        self._create_rule_helper('rule_04', {'logs': ['log_type_03']})

        # Check for 4 total rules
        assert len(rule.Rule._rules) == 4

        # Two rules should have log_type_01, and two should have log_type_02
        assert len(rule.Rule.rules_for_log_type('log_type_01')) == 2
        assert len(rule.Rule.rules_for_log_type('log_type_02')) == 2

        # Check to make sure the fourth rule has log_type_03
        result = rule.Rule.rules_for_log_type('log_type_03')
        assert len(result) == 1
        assert result[0].name == 'rule_04'

    def test_rule_outputs(self):
        """Rule - outputs is configured"""
        self._create_rule_helper(
            'test_rule', options={'logs': ['log_type_01'], 'outputs': ['aws-sns:test']}
        )

        result = rule.Rule._rules["test_rule"]

        # Verify outputs is configured
        assert result.outputs == ['aws-sns:test']

    def test_rule_outputs_set(self):
        """Rule - outputs, check outputs_set"""
        self._create_rule_helper(
            'test_rule',
            options={
                'logs': ['log_type_01'],
                'outputs': ['aws-sns:test', 'aws-sns:test'],
            },
        )

        result = rule.Rule._rules["test_rule"]

        # Verify outputs is configured
        assert result.outputs == ['aws-sns:test', 'aws-sns:test']
        assert isinstance(result.outputs_set, set)
        assert result.outputs_set == {'aws-sns:test'}

    def test_rule_dynamic_outputs(self):
        """Rule - dynamic_outputs is configured"""

        def dynamic_function():
            return "aws-sns:test"

        self._create_rule_helper(
            'test_rule',
            options={'logs': ['log_type_01'], 'dynamic_outputs': [dynamic_function]},
        )
        result = rule.Rule._rules["test_rule"]

        # Verify dynamic_outputs is configured
        assert result.dynamic_outputs == [dynamic_function]

    def test_rule_dynamic_outputs_set(self):
        """Rule - dynamic_outputs, check dynamic_outputs_set"""

        def dynamic_function():
            return "aws-sns:test"

        self._create_rule_helper(
            'test_rule',
            options={'logs': ['log_type_01'], 'dynamic_outputs': [dynamic_function]},
        )
        result = rule.Rule._rules["test_rule"]

        # Verify outputs is configured
        assert result.dynamic_outputs == [dynamic_function]
        assert isinstance(result.dynamic_outputs_set, set)
        assert result.dynamic_outputs_set == {dynamic_function}

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
from mock import patch

from stream_alert.shared import rule

from nose.tools import assert_equal, raises


class TestRule(object):
    """TestRule class"""
    def setup(self):
        rule.Rule._rules.clear()

    def teardown(self):
        rule.Rule._rules.clear()

    @staticmethod
    def _create_rule_helper(rule_name, options=None):

        if not options:
            options = {'logs': ['log_type_01']}

        # Create a rule from this code block, injecting the rule name
        custom_rule = """
@rule.rule(**options)
def {}(_):
    return False
""".format(rule_name)

        exec custom_rule #pylint: disable=exec-used

    def test_rule_valid(self):
        """Rule - Create Valid Rule"""
        self._create_rule_helper('test_rule')
        assert_equal(rule.Rule._rules.keys(), ['test_rule'])

    @raises(rule.RuleInvalid)
    def test_rule_invalid(self):
        """Rule - Create Rule, Missing Args"""
        # Rules must either have `logs` or `datatypes` defined
        self._create_rule_helper('test_rule', {'outputs': ['fake_output']})

    @raises(rule.RuleInvalid)
    def test_rule_exists(self):
        """Rule - Create Rule, Rule Already Exists"""
        # Rules must either have `logs` or `datatypes` defined
        self._create_rule_helper('test_rule')
        self._create_rule_helper('test_rule')

    def test_rule_disable(self):
        """Rule - Disabled Rule"""
        @rule.disable
        @rule.rule(logs=['log_type'])
        def test_rule_disabled(_): #pylint: disable=unused-variable
            return False

        assert_equal(rule.Rule._rules['test_rule_disabled'].disabled, True)

    def test_rule_to_string(self):
        """Rule - String Representation"""
        def test_rule(_):
            pass
        test_rule = rule.Rule(test_rule, outputs=['foo'], logs=['bar'])
        assert_equal(str(test_rule), '<Rule: test_rule; outputs: [\'foo\']; disabled: False>')
        assert_equal(repr(test_rule), '<Rule: test_rule; outputs: [\'foo\']; disabled: False>')

    @patch('logging.Logger.exception')
    def test_rule_process_exception(self, log_mock):
        """Rule - Process, Exeception"""
        def test_rule(_):
            return 1/0 == 0
        test_rule = rule.Rule(test_rule, logs=['bar'])
        result = test_rule.process(None)
        log_mock.assert_called_with('Encountered error with rule: %s', 'test_rule')
        assert_equal(result, False)

    def test_rule_process(self):
        """Rule - Process, Valid"""
        def test_rule(_):
            return True
        test_rule = rule.Rule(test_rule, logs=['bar'])
        result = test_rule.process(None)
        assert_equal(result, True)

    def test_rule_process_with_context(self):
        """Rule - Process, With Context"""
        def test_rule(_, rule_context): #pylint: disable=missing-docstring
            rule_context['relevant'] = 'data'
            return True
        test_rule = rule.Rule(test_rule, logs=['bar'], context={'output': 'context'})
        result = test_rule.process(None)
        assert_equal(result, True)
        assert_equal(test_rule.context['relevant'], 'data')

    def test_get_rule(self):
        """Rule - Get Rule"""
        rule_name = 'test_rule'
        self._create_rule_helper(rule_name)
        result = rule.Rule.get_rule(rule_name)
        assert_equal(result.rule_name, rule_name)

    def test_rule_names(self):
        """Rule - Get Rule Names"""
        rule_names = ['test_rule_01', 'test_rule_02']
        for name in rule_names:
            self._create_rule_helper(name)
        assert_equal(rule.Rule.rule_names(), rule_names)

    def test_get_rules_with_datatypes(self):
        """Rule - Get Rules, Rule With Datatypes"""
        # Add a rule (this one will have no datatypes)
        self._create_rule_helper('no_datatypes')

        # Add another rule with datatypes
        self._create_rule_helper('with_datatypes', {'datatypes': ['sourceAddress']})

        result = rule.Rule.rules_with_datatypes()
        # Make sure both rules are there
        assert_equal(len(rule.Rule.rule_names()), 2)
        # Check to see if the one with datatypes is returned
        assert_equal(len(result), 1)
        assert_equal(result[0].rule_name, 'with_datatypes')

    def test_get_rules_for_log_type(self):
        """Rule - Get Rules, For Log Type"""
        self._create_rule_helper('rule_01')
        self._create_rule_helper('rule_02', {'logs': ['log_type_02']})
        self._create_rule_helper('rule_03', {'logs': ['log_type_01', 'log_type_02']})
        self._create_rule_helper('rule_04', {'logs': ['log_type_03']})

        # Check for 4 total rules
        assert_equal(len(rule.Rule._rules), 4)

        # Two rules should have log_type_01, and two should have log_type_02
        assert_equal(len(rule.Rule.rules_for_log_type('log_type_01')), 2)
        assert_equal(len(rule.Rule.rules_for_log_type('log_type_02')), 2)

        # Check to make sure the fourth rule has log_type_03
        result = rule.Rule.rules_for_log_type('log_type_03')
        assert_equal(len(result), 1)
        assert_equal(result[0].rule_name, 'rule_04')

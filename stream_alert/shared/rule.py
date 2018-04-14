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
from stream_alert.shared import LOGGER
from stream_alert.shared.stats import time_rule

LOADED_MATCHERS = {}


class RuleInvalid(Exception):
    """Exeception to raise for any errors with invalid rules"""


def rule(**opts):
    """Register a rule that evaluates records"""
    def decorator(rule_func):
        """Rule decorator logic that returns instance of Rule"""
        return Rule(rule_func, **opts)
    return decorator


def disable(rule_instance):
    """Disables a rule from being run by removing it from the internal rules dict"""
    Rule.disable(rule_instance.rule_name)
    return rule_instance


def matcher(matcher_func):
    """Registers a matcher to be used with rules

    Matchers are rules which allow you to extract common logic
    into helper functions. Each rule can contain multiple matchers.
    """
    if matcher_func.__name__ in LOADED_MATCHERS:
        raise ValueError('matcher already defined: {}'.format(matcher_func.__name__))
    LOADED_MATCHERS[matcher_func.__name__] = matcher_func
    return matcher_func


class Rule(object):
    """Rule class to handle processing"""
    _rules = {}

    def __init__(self, func, **kwargs):
        self.func = func
        self.rule_name = func.__name__
        self.logs = kwargs.get('logs')
        self.outputs = kwargs.get('outputs')
        self.matchers = kwargs.get('matchers')
        self.datatypes = kwargs.get('datatypes')
        self.req_subkeys = kwargs.get('req_subkeys')
        self.context = kwargs.get('context', {})
        self.disabled = False

        if not (self.logs or self.datatypes):
            raise RuleInvalid(
                "Invalid rule [{}] - rule must have either 'logs' "
                "or 'datatypes' declared'".format(self.rule_name)
            )

        if self.rule_name in Rule._rules:
            raise RuleInvalid('Rule [{}] already defined'.format(self.rule_name))

        Rule._rules[self.rule_name] = self

    def __str__(self):
        return '<Rule: {}; outputs: {}; disabled: {}>'.format(
            self.rule_name,
            self.outputs,
            self.disabled
        )

    def __repr__(self):
        return self.__str__()

    @time_rule
    def process(self, rec):
        """Process will call this rule's function on the passed record

        Args:
            rec (dict): Record that this rule should be run against

        Returns:
            bool: True if this rule triggers for the passed record, False otherwise
        """
        try:
            if self.context:
                return self.func(rec, self.context)

            return self.func(rec)
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception('Encountered error with rule: %s', self.rule_name)

        return False

    @classmethod
    def disable(cls, name):
        cls._rules[name].disabled = True

    @classmethod
    def rule_names(cls):
        return Rule._rules.keys()

    @classmethod
    def get_rule(cls, rule_name):
        return Rule._rules.get(rule_name)

    @classmethod
    def rules_with_datatypes(cls):
        return [item for item in Rule._rules.values()
                if item.datatypes and not item.disabled]

    @classmethod
    def rules_for_log_type(cls, log_type):
        return [item for item in Rule._rules.values()
                if (item.logs is None or log_type in item.logs) and not item.disabled]

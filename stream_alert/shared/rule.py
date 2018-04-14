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


class RuleInvalid(Exception):
    """Exeception to raise for any errors with invalid rules"""


def rule(**opts):
    """Decorator to be used to register a rule"""
    def decorator(rule_func):
        """Rule decorator logic that returns instance of Rule"""
        return Rule(rule_func, **opts)
    return decorator


def disable(rule_instance):
    """Decorator to be used for disabling a rule"""
    Rule.disable(rule_instance.rule_name)
    return rule_instance


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
        self.initial_context = kwargs.get('context')
        self.context = None
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

    def check_matchers(self, record):
        """Run any rule matchers against the record

        Args:
            record (dict): Record that this rule should be run against

        Returns:
            bools: True if all matchers apply to this record, False otherwise
        """
        if not self.matchers:
            return True

        return all(Matcher.process(matcher_name, record) for matcher_name in self.matchers)

    @time_rule
    def process(self, record):
        """Process will call this rule's function on the passed record

        Args:
            record (dict): Record that this rule should be run against

        Returns:
            bool: True if this rule triggers for the passed record, False otherwise
        """
        try:
            # The initial_context object must be copied. This avoids
            # bleed over from other runs of the rule using the same
            # context object
            if self.initial_context is not None:
                self.context = self.initial_context.copy()
                return self.func(record, self.context)

            return self.func(record)
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


class MatcherInvalid(Exception):
    """Exeception to raise for any errors with invalid matchers"""


def matcher(matcher_func):
    """Decorator to be used to register a matcher for use with rules

    Matchers extract common logic into helper functions. Each rule
    can contain multiple matchers.
    """
    Matcher(matcher_func)
    return matcher_func


class Matcher(object):
    """Matcher class to handle matcher logic"""
    _matchers = {}
    def __init__(self, func):
        if func.__name__ in Matcher._matchers:
            raise MatcherInvalid('matcher already defined: {}'.format(func.__name__))

        # Register the matcher
        Matcher._matchers[func.__name__] = func

    @classmethod
    def process(cls, matcher_from_rule, record):
        """Process will ensure this record is valid for this matcher

        Args:
            matcher_from_rule (str): Name of matcher supplied in the rule decorator
            record (dict): Record that the matcher should be applied against

        Returns:
            bool: True if the matcher applied to this record, False otherwise
        """
        func = Matcher._matchers.get(matcher_from_rule)
        if not func:
            # TODO: previously, if a matcher used in a rule did not exist,
            #  we would log an error but not return False. Should an invalid
            #  matcher in a rule throw and error or be ignored? See here:
            # https://github.com/airbnb/streamalert/blob/c33709129ee2bd9cd38f50f3e95fc7d01518e539/stream_alert/rule_processor/rules_engine.py#L162-L163
            # TODO: is there any reason we shouldn't just import thee matcher into
            #  the rule file, instead of referring to it by the function's name?
            LOGGER.error('The matcher [%s] does not exist!', matcher_from_rule)
            return False

        try:
            return func(record)
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception('Encountered error with matcher: %s', func.__name__)

        return False

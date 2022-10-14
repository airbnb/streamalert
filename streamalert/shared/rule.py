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
import ast
import hashlib
import inspect
import json
from copy import deepcopy

from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


class RuleCreationError(Exception):
    """Exception to raise for any errors with invalid rules"""


def rule(**opts):
    """Decorator to be used to register a rule"""
    def decorator(rule_func):
        """Rule decorator logic that returns instance of Rule"""
        return Rule(rule_func, **opts)

    return decorator


def disable(rule_instance):
    """Decorator to be used for disabling a rule"""
    Rule.disable(rule_instance.name)
    return rule_instance


class Rule:
    """Rule class to handle processing"""
    DEFAULT_RULE_DESCRIPTION = 'No rule description provided'
    CHECKSUM_UNKNOWN = 'checksum unknown'

    _rules = {}

    def __init__(self, func, **kwargs):
        self.func = func
        self.name = func.__name__
        self.datatypes = kwargs.get('datatypes')
        self.logs = kwargs.get('logs')
        self.matchers = kwargs.get('matchers')
        self.merge_by_keys = kwargs.get('merge_by_keys')
        self.merge_window_mins = kwargs.get('merge_window_mins') or 0
        self.outputs = kwargs.get('outputs')
        self.dynamic_outputs = kwargs.get('dynamic_outputs')
        self.publishers = kwargs.get('publishers')
        self.req_subkeys = kwargs.get('req_subkeys')
        self.initial_context = kwargs.get('context')
        self.context = None
        self.disabled = False
        self._description = func.__doc__
        self._checksum = None

        if not (self.logs or self.datatypes):
            raise RuleCreationError(
                f"Invalid rule [{self.name}] - rule must have either 'logs' or 'datatypes' declared'"
            )

        if self.name in Rule._rules:
            raise RuleCreationError(f'Rule [{self.name}] already defined')

        Rule._rules[self.name] = self

    def __str__(self):
        return f'<Rule: {self.name}; outputs: {self.outputs}; disabled: {self.disabled}>'

    def __repr__(self):
        return self.__str__()

    def check_matchers(self, record):
        """Run any rule matchers against the record

        Args:
            record (dict): Record that this rule should be run against

        Returns:
            bools: True if all matchers apply to this record, False otherwise
        """
        return all(self._run_matcher(func, record)
                   for func in self.matchers) if self.matchers else True

    @classmethod
    def _run_matcher(cls, func, record):
        """Process will ensure this record is valid for this matcher

        Args:
            func (function): Matcher function supplied in the rule decorator
            record (dict): Record that the matcher should be applied against

        Returns:
            bool: True if the matcher applied to this record, False otherwise
        """
        try:
            return func(record)
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception('Encountered error with matcher: %s', func.__name__)

        return False

    def is_staged(self, rule_table):
        """Run any rule matchers against the record

        Args:
            rule_table (RuleTable): Front end for DynamoDB rule table to do rule info lookups

        Returns:
            bools: True if this rule is staged, False otherwise
        """
        if not rule_table:
            return False

        rule_info = rule_table.rule_info(self.name)
        return rule_info.get('Staged', False) if rule_info else False

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
                self.context = deepcopy(self.initial_context)
                return self.func(record, self.context)

            return self.func(record)
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception('Encountered error with rule: %s', self.name)
            LOGGER.error('Record that resulted in error:\n%s', json.dumps(record))

        return False

    @property
    def checksum(self):
        """Produce an md5 for the contents of this rule.

        This logic applies to expressions within the function only. It does not take
        into account: the function name, docstring, comments, or decorator arguments
        """
        if not self._checksum:
            try:
                code = inspect.getsource(self.func)
                root = ast.parse(code)
                md5 = hashlib.md5()  # nosec
                for expression in root.body[0].body:
                    # This check is necessary to ensure changes to the docstring
                    # are allowed without altering the checksum
                    if not isinstance(expression, ast.Expr):
                        md5.update(ast.dump(expression).encode('utf-8'))

                self._checksum = md5.hexdigest()
            except (TypeError, IndentationError, IndexError):
                LOGGER.exception('Could not checksum rule function')
                self._checksum = self.CHECKSUM_UNKNOWN

        return self._checksum

    @property
    def description(self):
        return self._description or self.DEFAULT_RULE_DESCRIPTION

    @description.setter
    def description(self, description):
        self._description = str(description)

    @property
    def outputs_set(self):
        return set(self.outputs or [])

    @property
    def dynamic_outputs_set(self):
        return set(self.dynamic_outputs or [])

    @classmethod
    def disabled_rules(cls):
        return {name for name, rule in cls._rules.items() if rule.disabled}

    @classmethod
    def disable(cls, name):
        cls._rules[name].disabled = True

    @classmethod
    def get_rule(cls, rule_name):
        return Rule._rules.get(rule_name)

    @classmethod
    def rule_names(cls):
        return list(Rule._rules.keys())

    @classmethod
    def rules_with_datatypes(cls):
        return [item for item in list(Rule._rules.values()) if item.datatypes and not item.disabled]

    @classmethod
    def rules_for_log_type(cls, log_type):
        return [
            item for item in list(Rule._rules.values())
            if (item.logs is None or log_type in item.logs) and not item.disabled
        ]

'''
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
'''

import copy
import logging

from collections import namedtuple

logging.basicConfig()
logger = logging.getLogger('StreamAlert')
logger.setLevel(logging.INFO)

class StreamRules(object):
    """Container class for StreamAlert Rules

    The __rules dictionary stores rules with the following metadata:
        key: Name of the rule
        value: Named tuple (rule function, outputs, matchers, logs)

    Example:
        __rules[root_logins]: (<root_logins function>, ['pagerduty'], ['prod'], ['osquery'])

    the __matchers dictionary stores:
        Key: The name of the matcher
        Value: The matcher function
    """
    __rules = {}
    __matchers = {}

    @classmethod
    def rule(cls, rule_name, **opts):
        """Register a rule that evaluates records against rules.

        A rule maps events (by `logs`) to a function that accepts an event
        and returns a boolean. If the function returns `True`, then the event is
        passed on to the sink(s). If the function returns `False`, the event is
        dropped.
        """
        rule_attrs = namedtuple('Rule', ['rule_name',
                                        'rule_function',
                                        'matchers',
                                        'logs',
                                        'outputs',
                                        'req_subkeys'])

        def decorator(rule):
            logs = opts.get('logs')
            outputs = opts.get('outputs')
            matchers = opts.get('matchers')
            req_subkeys = opts.get('req_subkeys')

            if not all([logs, outputs]):
                logger.error('Invalid rule [%s]', rule_name)
                return

            if rule_name in cls.__rules:
                raise ValueError('rule [{}] already defined'.format(rule_name))
            cls.__rules[rule_name] = rule_attrs(rule_name,
                                               rule,
                                               matchers,
                                               logs,
                                               outputs,
                                               req_subkeys)
            return rule
        return decorator

    @classmethod
    def matcher(cls, name):
        """Registers a matcher rule.

        Matchers are rules which allow you to extract common logic
        into helper functions. Each rule can contain multiple matchers.
        """
        def decorator(matcher):
            if name in cls.__matchers:
                raise ValueError('matcher already defined: {}'.format(name))
            cls.__matchers[name] = matcher
            return matcher
        return decorator

    @classmethod
    def match_event(cls, record, rule):
        """Evaluate matchers on a record.

        Given a list of matchers, evaluate a record through each
        to find a match.  If any matcher is evaluated as false,
        the loop breaks and no further matchers are evaluated.
        Otherwise, returns True.

        Args:
            payload: The log to process.
            matcher_names: All matchers for a given rule to process.

        Returns:
            Boolean result of matcher processing.
        """
        # matchers are optional for rules
        if not rule.matchers:
            return True

        for matcher in rule.matchers:
            matcher_function = cls.__matchers.get(matcher)
            if matcher_function:
                try:
                    matcher_result = matcher_function(record)
                except Exception as e:
                    matcher_result = False
                    logger.error('%s: %s', matcher_function.__name__, e.message)
                if not matcher_result:
                    return False
            else:
                logger.error('The matcher [%s] does not exist!', matcher)

        return True

    @classmethod
    def process_rule(cls, record, rule):
        try:
            rule_result = rule.rule_function(record)
        except Exception as e:
            rule_result = False
            logger.error('%s: %s', rule.rule_function.__name__, e.message)
        return rule_result

    @classmethod
    def process_subkeys(cls, record, payload_type, rule):
        """Check payload record contains all subkeys needed for rules

        Because each log is processed by every rule for a given log type,
        it's possible that a rule references a subkey that doesn't exist in
        that specific log. This method verifies that the declared subkeys
        in a rule are contained in the JSON payload prior to rule processing.

        Args:
            payload: Log to process
            rule: Rule attributes

        Returns:
            Boolean result of subkey check.
        """
        if not rule.req_subkeys or payload_type != 'json':
            return True
        else:
            for key, nested_keys in rule.req_subkeys.iteritems():
                if not all(x in record[key] for x in nested_keys):
                    return False
            return True

    @classmethod
    def process(cls, input_payload):
        """Process rules on a record.

        Gather a list of rules based on the record's datasource type.
        For each rule, evaluate the record through all listed matchers
        and the rule itself to determine if a match occurs.

        Returns:
            List of alerts. 

            An alert is represented as a dictionary with the following keys:
                rule_name: the name of the triggered rule
                payload: the StreamPayload object
                outputs: list of outputs to send to
        """
        rules = []
        alerts = []
        payload = copy.copy(input_payload)

        for rule_name, rule_attrs in cls.__rules.iteritems():
            if payload.log_source in rule_attrs.logs:
                rules.append(rule_attrs)

        if len(rules) > 0:
            for record in payload.records:
                for rule in rules:
                    # subkey check
                    has_sub_keys = cls.process_subkeys(record,
                                                       payload.type,
                                                       rule)
                    if not has_sub_keys:
                        continue

                    # matcher check
                    matcher_result = cls.match_event(record, rule)
                    if not matcher_result:
                        continue

                    # rule analysis
                    rule_result = cls.process_rule(record, rule)
                    if rule_result:
                        alert = {
                            'rule_name': rule.rule_name,
                            'record': record,
                            'metadata': {
                                'log': str(payload.log_source),
                                'outputs': rule.outputs,
                                'type': payload.type,
                                'source': {
                                    'service': payload.service,
                                    'entity': payload.entity
                                }
                            }
                        }
                        alerts.append(alert)

        return alerts

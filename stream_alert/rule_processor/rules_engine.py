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
from collections import namedtuple
from copy import copy
import json

from stream_alert.rule_processor import LOGGER

DEFAULT_RULE_DESCRIPTION = 'No rule description provided'

RuleAttributes = namedtuple('Rule', ['rule_name',
                                     'rule_function',
                                     'matchers',
                                     'datatypes',
                                     'logs',
                                     'outputs',
                                     'req_subkeys'])


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
    def get_rules(cls):
        """Helper method to return private class property of __rules"""
        return cls.__rules

    @classmethod
    def rule(cls, **opts):
        """Register a rule that evaluates records against rules.

        A rule maps events (by `logs`) to a function that accepts an event
        and returns a boolean. If the function returns `True`, then the event is
        passed on to the sink(s). If the function returns `False`, the event is
        dropped.
        """
        def decorator(rule):
            """Rule decorator logic."""
            rule_name = rule.__name__
            logs = opts.get('logs')
            outputs = opts.get('outputs')
            matchers = opts.get('matchers')
            datatypes = opts.get('datatypes')
            req_subkeys = opts.get('req_subkeys')

            if not (logs or datatypes):
                LOGGER.error(
                    'Invalid rule [%s] - rule must have either \'logs\' or \''
                    'datatypes\' declared',
                    rule_name)
                return

            if not outputs:
                LOGGER.error(
                    'Invalid rule [%s] - rule must have \'outputs\' declared',
                    rule_name)
                return

            if rule_name in cls.__rules:
                raise ValueError('rule [{}] already defined'.format(rule_name))
            cls.__rules[rule_name] = RuleAttributes(rule_name,
                                                    rule,
                                                    matchers,
                                                    datatypes,
                                                    logs,
                                                    outputs,
                                                    req_subkeys)
            return rule
        return decorator

    @classmethod
    def matcher(cls):
        """Registers a matcher rule.

        Matchers are rules which allow you to extract common logic
        into helper functions. Each rule can contain multiple matchers.
        """
        def decorator(matcher):
            """Match decorator."""
            name = matcher.__name__
            if name in cls.__matchers:
                raise ValueError('matcher already defined: {}'.format(name))
            cls.__matchers[name] = matcher
            return matcher
        return decorator

    @classmethod
    def disable(cls):
        """Disables a rule from being run by removing it from the internal rules dict"""
        def decorator(rule):
            """Rule disable decorator."""
            rule_name = rule.__name__
            if rule_name in cls.__rules:
                del cls.__rules[rule_name]
            return rule
        return decorator

    @classmethod
    def match_event(cls, record, rule):
        """Evaluate matchers on a record.

        Given a list of matchers, evaluate a record through each
        to find a match.  If any matcher is evaluated as false,
        the loop breaks and no further matchers are evaluated.
        Otherwise, returns True.

        Args:
            record: Record to be matched
            rule: Rule containing the list of matchers

        Returns:
            bool: result of matcher processing
        """
        # matchers are optional for rules
        if not rule.matchers:
            return True

        for matcher in rule.matchers:
            matcher_function = cls.__matchers.get(matcher)
            if matcher_function:
                try:
                    matcher_result = matcher_function(record)
                except Exception as err:  # pylint: disable=broad-except
                    matcher_result = False
                    LOGGER.error('%s: %s', matcher_function.__name__, err.message)
                if not matcher_result:
                    return False
            else:
                LOGGER.error('The matcher [%s] does not exist!', matcher)

        return True

    @classmethod
    def match_types(cls, record, normalized_types, datatypes):
        """Match normalized types against record

        Args:
            record (dict): Parsed payload of any log
            normalized_types (dict): Normalized types
            datatypes (list): defined in rule options, normalized_types users
                interested in.

        Returns:
            (dict): A dict of normalized_types with original key names

        Example 1:
            datatypes=['defined_type1', 'defined_type2', 'not_defined_type']
            This method will return an empty dictionary and log datatypes
                "not defined" error to Logger.

        Example 2:
            datatypes=['defined_type1', 'defined_type2']
            This method will return an dictionary :
                {
                    "defined_type1": [[original_key1]],
                    "defined_type2": [[original_key2, sub_key2], [original_key3]]
                }
        """
        results = dict()
        if not (datatypes and cls.validate_datatypes(normalized_types, datatypes)):
            return results

        return cls.match_types_helper(record, normalized_types, datatypes)

    @classmethod
    def match_types_helper(cls, record, normalized_types, datatypes):
        """Helper method to recursively visit all subkeys

        Args:
            record (dict): Parsed data
            normalized_types (dict): Normalized types
            datatypes (list): Normalized types users interested in

        Returns:
            (dict): A dict of normalized_types with original key names
        """
        results = dict()
        for key, val in record.iteritems():
            if key == 'normalized_types':
                continue
            if isinstance(val, dict):
                nested_results = cls.match_types_helper(val, normalized_types, datatypes)
                cls.update(results, key, nested_results)
            else:
                for datatype in datatypes:
                    if key in normalized_types[datatype]:
                        if not datatype in results:
                            results[datatype] = [[key]]
                        else:
                            results[datatype].append([key])
        return results

    @classmethod
    def update(cls, results, parent_key, nested_results):
        """Update nested_results by inserting parent key to beginning of list.
        Also combine results and nested_results into one dictionary

        Args:
            results (dict): A dict of normalized_types with original key names
            parent_key (str): Parent key of values in nested_results. The values
                in nested_results are original keys of normalized types.
            nested_results (dict): A dict of normalized_types from nested record

        Example 1:
            results = {
                'ipv4': [['key1']]
            }
            parent_key = 'key2'
            nested_results = {
                'username': [['sub_key1']],
                'ipv4': [['sub_key2']]
            }

            This method will update nested_results to:
            {
                'username': [['key2', 'sub_key1']],
                'ipv4': [['key2', 'sub_key2']]
            }

            Also it will combine nested_results to results:
            {
                'ipv4': [['key1'], ['key2', 'sub_key2']],
                'username': [['key2', 'sub_key1']]
            }
        """
        for key, val in nested_results.iteritems():
            if isinstance(val, list):
                for item in val:
                    item.insert(0, parent_key)
            else:
                val.insert(0, parent_key)

            if key in results:
                results[key] += val
            else:
                if isinstance(val, list):
                    results[key] = val
                else:
                    results[key] = [val]

    @classmethod
    def validate_datatypes(cls, normalized_types, datatypes):
        """Check is datatype valid

        Args:
            normalized_types (dict): normalized_types for certain log
            datatypes (list): defined in rule options, users interested types

        Returns:
            (boolean): return true if all datatypes are defined
        """
        if not normalized_types:
            return False

        for datatype in datatypes:
            if not datatype in normalized_types:
                return False
        return True

    @classmethod
    def process_rule(cls, record, rule):
        """Process rule functions on a given record

        Args:
            record (dict): Parsed payload of any type
            rule (func): Rule function to process the record

        Returns:
            (bool): The return function of the rule
        """
        try:
            rule_result = rule.rule_function(record)
        except Exception:  # pylint: disable=broad-except
            rule_result = False
            LOGGER.exception(
                'Encountered error with rule: %s',
                rule.rule_function.__name__)
        return rule_result

    @classmethod
    def process_subkeys(cls, record, payload_type, rule):
        """Check payload record contains all subkeys needed for rules

        Because each log is processed by every rule for a given log type,
        it's possible that a rule references a subkey that doesn't exist in
        that specific log. This method verifies that the declared subkeys
        in a rule are contained in the JSON payload prior to rule processing.

        Args:
            record: Payload record to process
            payload_type (str): type of the record
            rule: Rule attributes

        Returns:
            bool: result of subkey check.
        """
        if not rule.req_subkeys or payload_type != 'json':
            return True

        for key, nested_keys in rule.req_subkeys.iteritems():
            # This is an extra layer of protection when
            # verifying a subkey exists in a record with a null value.
            # In the case of CloudTrail, a top level key has been
            # observed as either a map with subkeys, or null.
            if not record.get(key):
                LOGGER.debug(
                    'The required subkey %s is not found when trying to process %s: \n%s',
                    key,
                    rule.rule_name,
                    json.dumps(
                        record,
                        indent=2))
                return False
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
            list: alerts

            An alert is represented as a dictionary with the following keys:
                rule_name: the name of the triggered rule
                payload: the StreamPayload object
                outputs: list of outputs to send to
        """
        alerts = []
        payload = copy(input_payload)

        rules = [rule_attrs for rule_attrs in cls.__rules.values()
                 if rule_attrs.logs is None or payload.log_source in rule_attrs.logs]

        if not rules:
            LOGGER.debug('No rules to process for %s', payload)
            return alerts

        for record in payload.records:
            for rule in rules:
                # subkey check
                has_sub_keys = cls.process_subkeys(record, payload.type, rule)
                if not has_sub_keys:
                    continue

                # matcher check
                matcher_result = cls.match_event(record, rule)
                if not matcher_result:
                    continue
                if rule.datatypes:
                    types_result = cls.match_types(record,
                                                   payload.normalized_types,
                                                   rule.datatypes)
                    record['normalized_types'] = types_result

                # rule analysis
                rule_result = cls.process_rule(record, rule)
                if rule_result:
                    LOGGER.info('Rule [%s] triggered an alert on log type [%s] from entity \'%s\' '
                                'in service \'%s\'', rule.rule_name, payload.log_source,
                                payload.entity, payload.service())
                    alert = {
                        'record': record,
                        'rule_name': rule.rule_name,
                        'rule_description': rule.rule_function.__doc__ or DEFAULT_RULE_DESCRIPTION,
                        'log_source': str(payload.log_source),
                        'log_type': payload.type,
                        'outputs': rule.outputs,
                        'source_service': payload.service(),
                        'source_entity': payload.entity}
                    alerts.append(alert)

        return alerts

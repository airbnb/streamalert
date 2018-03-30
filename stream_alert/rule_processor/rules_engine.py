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
import uuid

from stream_alert.rule_processor import LOGGER
from stream_alert.rule_processor.threat_intel import StreamThreatIntel
from stream_alert.shared import NORMALIZATION_KEY, resources

DEFAULT_RULE_DESCRIPTION = 'No rule description provided'

RuleAttributes = namedtuple('Rule', ['rule_name',
                                     'rule_function',
                                     'matchers',
                                     'datatypes',
                                     'logs',
                                     'outputs',
                                     'req_subkeys',
                                     'context'])


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

    def __init__(self, config):
        """Initialize a StreamRules instance to cache a StreamThreatIntel instance."""
        self._threat_intel = StreamThreatIntel.load_from_config(config)
        self._required_outputs_set = resources.get_required_outputs()

    @classmethod
    def get_rules(cls):
        """Helper method to return private class property of __rules"""
        return cls.__rules

    @classmethod
    def rule(cls, **opts):
        """Register a rule that evaluates records against rules.

        A rule maps events (by `logs`) to a function that accepts an event
        and returns a boolean. If the function returns `True`, then the event is
        passed on to the alert forwarder. If the function returns `False`, the event is
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
            context = opts.get('context', {})

            if not (logs or datatypes):
                LOGGER.error(
                    'Invalid rule [%s] - rule must have either \'logs\' or \''
                    'datatypes\' declared',
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
                                                    req_subkeys,
                                                    context)
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

    def match_event(self, record, rule):
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
            matcher_function = self.__matchers.get(matcher)
            if matcher_function:
                try:
                    matcher_result = matcher_function(record)
                except Exception as err:  # pylint: disable=broad-except
                    matcher_result = False
                    LOGGER.error('Matcher \'%s\' failed with error: %s',
                                 matcher_function.__name__, err.message)
                if not matcher_result:
                    return False
            else:
                LOGGER.error('The matcher [%s] does not exist!', matcher)

        return True

    @staticmethod
    def match_types(record, normalized_types, datatypes):
        """Match normalized types against record

        Args:
            record (dict): Parsed payload of any log
            normalized_types (dict): Normalized types
            datatypes (list): defined in rule options, normalized_types users
                interested in.

        Returns:
            dict: A dict of normalized_types with original key names

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
        if not (datatypes and normalized_types):
            return

        return StreamRules.match_types_helper(record, normalized_types, datatypes)

    @staticmethod
    def match_types_helper(record, normalized_types, datatypes):
        """Helper method to recursively visit all subkeys

        Args:
            record (dict): Parsed data
            normalized_types (dict): Normalized types
            datatypes (list): Normalized types users interested in

        Returns:
            dict: A dict of normalized_types with original key names
        """
        results = dict()
        for key, val in record.iteritems():
            if key == NORMALIZATION_KEY:
                continue
            if isinstance(val, dict):
                nested_results = StreamRules.match_types_helper(val, normalized_types, datatypes)
                StreamRules.update(results, key, nested_results)
            else:
                for datatype in datatypes:
                    if datatype in normalized_types and key in normalized_types[datatype]:
                        if not datatype in results:
                            results[datatype] = [[key]]
                        else:
                            results[datatype].append([key])
        return results

    @staticmethod
    def update(results, parent_key, nested_results):
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

    @staticmethod
    def process_rule(record, rule):
        """Process rule functions on a given record

        Args:
            record (dict): Parsed payload of any type
            rule (func): Rule function to process the record

        Returns:
            bool: The return function of the rule
        """
        try:
            if rule.context:
                rule_result = rule.rule_function(record, rule.context)
            else:
                rule_result = rule.rule_function(record)
        except Exception:  # pylint: disable=broad-except
            rule_result = False
            LOGGER.exception(
                'Encountered error with rule: %s',
                rule.rule_function.__name__)
        return rule_result

    @staticmethod
    def process_subkeys(record, payload_type, rule):
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
                    key, rule.rule_name, record)
                return False
            if not all(record[key].get(x) for x in nested_keys):
                return False

        return True

    def process(self, input_payload):
        """Process rules on a record.

        Gather a list of rules based on the record's datasource type.
        For each rule, evaluate the record through all listed matchers
        and the rule itself to determine if a match occurs.

        Returns:
            A tuple(list, list).
                First return is a list of alerts.
                Second return is a list of payload instance with normalized records.
        """
        alerts = []
        # store normalized records for future process in Threat Intel
        normalized_records = []
        payload = copy(input_payload)

        rules = [rule_attrs for rule_attrs in self.__rules.values()
                 if rule_attrs.logs is None or payload.log_source in rule_attrs.logs]

        if not rules:
            LOGGER.debug('No rules to process for %s', payload)
            return alerts, normalized_records

        for record in payload.records:
            # One record may be added to normalized records list multiple time due
            # to each record is processed by all rules.
            normalized_record_appended = False
            for rule in rules:
                # subkey check
                has_sub_keys = self.process_subkeys(record, payload.type, rule)
                if not has_sub_keys:
                    continue

                # matcher check
                matcher_result = self.match_event(record, rule)
                if not matcher_result:
                    continue

                types_result = None
                if rule.datatypes:
                    types_result = self.match_types(record,
                                                    payload.normalized_types,
                                                    rule.datatypes)

                if types_result:
                    record_copy = record.copy()
                    record_copy[NORMALIZATION_KEY] = types_result
                    if self._threat_intel and not normalized_record_appended:
                        # A copy of payload which includes payload metadata.
                        # The payload metadata includes log_source, type, service,
                        # and entity. The metadata will be returned to along with
                        # normalized record for threat detection.
                        payload_copy = copy(input_payload)
                        payload_copy.pre_parsed_record = record_copy
                        payload_copy.records = None
                        payload_copy.raw_record = None
                        normalized_records.append(payload_copy)
                        normalized_record_appended = True
                else:
                    record_copy = record
                # rule analysis
                self.rule_analysis(record_copy, rule, payload, alerts)

        return alerts, normalized_records



    def threat_intel_match(self, payload_with_normalized_records):
        """Apply Threat Intelligence on normalized records

        Args:
            payload_with_normalized_records (list): A list of payload instances.
                And it pre_parsed_record is replaced by normalized record. The
                reason to pass a copy of payload into Threat Intelligence is because
                alerts require to include payload metadata (payload.log_source,
                payload.type, payload.service and payload.entity).

        Returns:
            list: A list of alerts triggered by Threat Intelligence.
        """
        alerts = []
        if self._threat_intel:
            ioc_records = self._threat_intel.threat_detection(payload_with_normalized_records)
            rules = [rule_attrs for rule_attrs in self.__rules.values()
                     if rule_attrs.datatypes]
            if ioc_records:
                for ioc_record in ioc_records:
                    for rule in rules:
                        self.rule_analysis(ioc_record.pre_parsed_record, rule, ioc_record, alerts)
        return alerts

    def rule_analysis(self, record, rule, payload, alerts):
        """Class method to analyze rule against a record

        Args:
            record (dict): A parsed log with data.
            rule: Rule attributes.
            payload: The StreamPayload object.
            alerts (list): A list of alerts which will be sent to alert processor.

        Returns:
            dict: A list of alerts.
        """
        rule_result = StreamRules.process_rule(record, rule)
        if rule_result:
            if StreamRules.check_alerts_duplication(record, rule, alerts):
                return

            alert_id = str(uuid.uuid4())  # Random unique alert ID
            LOGGER.info('Rule [%s] triggered alert [%s] on log type [%s] from entity \'%s\' '
                        'in service \'%s\'', rule.rule_name, alert_id, payload.log_source,
                        payload.entity, payload.service())

            # Combine the required alert outputs with the ones for this rule
            all_outputs = self._required_outputs_set.union(set(rule.outputs or []))

            alert = {
                'id': alert_id,
                'record': record,
                'rule_name': rule.rule_name,
                'rule_description': rule.rule_function.__doc__ or DEFAULT_RULE_DESCRIPTION,
                'log_source': str(payload.log_source),
                'log_type': payload.type,
                'outputs': list(all_outputs), # TODO: @austinbyers - change this to a set
                'source_service': payload.service(),
                'source_entity': payload.entity,
                'context': rule.context}

            alerts.append(alert)

    @staticmethod
    def check_alerts_duplication(record, rule, alerts):
        """The method to check if the record has been added to alerts list already.

        The reason we need to do check alerts duplication is because original records
        would be modified by inserting normalization or/and IOC information if there
        exist. Threat Intel feature will process normalized records again and it
        will result alert duplication.

        Args:
            record (dict): A parsed log with data.
            rule: Rule attributes.
            alerts (list): A list of alerts which will be sent to alert processor.

        Returns:
            bool: Return True if both record and rule name exist in alerts list.
        """
        for exist_alert in alerts:
            if rule.rule_name == exist_alert['rule_name']:
                record_copy = record.copy()
                if StreamThreatIntel.IOC_KEY not in exist_alert['record']:
                    record_copy.pop(StreamThreatIntel.IOC_KEY, None)
                if NORMALIZATION_KEY not in exist_alert['record']:
                    record_copy.pop(NORMALIZATION_KEY, None)
                if record_copy == exist_alert['record']:
                    return True

        return False

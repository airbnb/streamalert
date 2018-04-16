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
from copy import copy
from datetime import timedelta
import os

from stream_alert.rule_processor import LOGGER
from stream_alert.rule_processor.threat_intel import StreamThreatIntel
from stream_alert.shared import NORMALIZATION_KEY, resources
from stream_alert.shared.alert import Alert
from stream_alert.shared.rule import import_folders, Rule


_IGNORE_KEYS = {StreamThreatIntel.IOC_KEY, NORMALIZATION_KEY}


class RulesEngine(object):
    """Class to act as a rules engine that processes rules"""
    def __init__(self, config):
        """Initialize a RulesEngine instance to cache a StreamThreatIntel instance."""
        self._threat_intel = StreamThreatIntel.load_from_config(config)
        self._required_outputs_set = resources.get_required_outputs()
        import_folders(*[item for location in {'rule_locations', 'matcher_locations'}
                         for item in config['global']['general'][location]])

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

        return RulesEngine.match_types_helper(record, normalized_types, datatypes)

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
                nested_results = RulesEngine.match_types_helper(val, normalized_types, datatypes)
                RulesEngine.update(results, key, nested_results)
            else:
                for datatype in datatypes:
                    if datatype in normalized_types and key in normalized_types[datatype]:
                        if datatype not in results:
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

    def run(self, input_payload):
        """Process rules on a record.

        Gather a list of rules based on the record's datasource type.
        For each rule, evaluate the record through all listed matchers
        and the rule itself to determine if a match occurs.

        Returns:
            A tuple(list, list).
                First return is a list of Alert instances.
                Second return is a list of payload instance with normalized records.
        """
        alerts = []
        # store normalized records for future process in Threat Intel
        normalized_records = []
        payload = copy(input_payload)

        rules = Rule.rules_for_log_type(payload.log_source)

        if not rules:
            LOGGER.debug('No rules to process for %s', payload)
            return alerts, normalized_records

        for record in payload.records:
            for rule in rules:
                # matcher check
                if not rule.check_matchers(record):
                    continue

                # subkey check
                if not self.process_subkeys(record, payload.type, rule):
                    continue

                if rule.datatypes:
                    # When rule 'datatypes' option is defined, rules engine will
                    # apply data normalization to all the record.
                    record_copy = self._apply_normalization(record, normalized_records,
                                                            rule, payload)
                    self.rule_analysis(record_copy, rule, payload, alerts)
                else:
                    self.rule_analysis(record, rule, payload, alerts)

        return alerts, normalized_records

    def _apply_normalization(self, record, normalized_records, rule, payload):
        """Apply data normalization to current record

        Args:
            record (dict): The parsed log w/wo data normalization.
            normalized_records (list): Contains a list of payload objects which
                have been normalized.
            rule (namedtuple): Contains alerting logic.
            payload (namedtuple): Contains parsed logs.
        """
        normalized, normalized_payload = self._is_normalized(record,
                                                             normalized_records,
                                                             rule.datatypes)

        if normalized:
            # If the record has been normalized, use normalized record copy
            record_copy = normalized_payload.pre_parsed_record
        else:
            # If the record has been normalized, apply normalization logic to the record
            # and insert normalization result to the record.
            types_result = self.match_types(record,
                                            payload.normalized_types,
                                            rule.datatypes)

            if types_result:
                record_copy = record.copy()

                # Insert normalization result to the record copy.
                record_copy[NORMALIZATION_KEY] = types_result

                if self._threat_intel:
                    # If threat intel is enabled, add newly normalized record to
                    # the list for future threat detection.
                    self._update_normalized_record(payload, record_copy, normalized_records)

            else:
                record_copy = record

        return record_copy

    @staticmethod
    def _update_normalized_record(payload, record_copy, normalized_records):
        """Add normalized record to a list for future threat detection

        Args:
            payload (namedtuple): Contains parsed logs.
            record_copy (dict): Contains log data with normalization information.
            normalized_records (list): Contains a list of payload objects
                with normalized records.
        """
        # It is required to have payload 'log_source', 'type', 'service' and 'entity'
        # information when analyzing record and triggering alert later. So here,
        # we make a copy of payload and reset unneccessary fields ('record', 'raw_record')
        payload_copy = copy(payload)
        payload_copy.pre_parsed_record = record_copy
        payload_copy.records = None
        payload_copy.raw_record = None
        normalized_records.append(payload_copy)

    def _is_normalized(self, record, normalized_records, datatypes):
        """Check if the current record has been normalized

        A record may be normalized multiple time only by different set of data types.

        Args:
            record (dict): The parsed log w/wo data normalization.
            normalized_records (list): Contains a list of payload objects
                with normalized records.
            datatypes (list): Normalized types defined in the Rule options.

        Return:
            bool: Return True if current record has been found in normalized records.
            namedtuple: A payload object contains normalized record.
        """
        for payload in normalized_records:
            if self._is_equal(record, payload.pre_parsed_record):
                if set(datatypes) - set(payload.pre_parsed_record.get(NORMALIZATION_KEY)):
                    continue
                else:
                    # if all datatypes have been normalized in a record, we should not do
                    # again
                    return True, payload
        return False, None

    def threat_intel_match(self, payload_with_normalized_records):
        """Apply Threat Intelligence on normalized records

        Args:
            payload_with_normalized_records (list): A list of payload instances.
                And it pre_parsed_record is replaced by normalized record. The
                reason to pass a copy of payload into Threat Intelligence is because
                alerts require to include payload metadata (payload.log_source,
                payload.type, payload.service and payload.entity).

        Returns:
            list: A list of Alerts triggered by Threat Intelligence.
        """
        alerts = []
        if self._threat_intel:
            ioc_records = self._threat_intel.threat_detection(payload_with_normalized_records)
            rules = Rule.rules_with_datatypes()
            if ioc_records:
                for ioc_record in ioc_records:
                    for rule in rules:
                        self.rule_analysis(ioc_record.pre_parsed_record, rule, ioc_record, alerts)
        return alerts

    def rule_analysis(self, record, rule, payload, alerts):
        """Analyze a rule against the record, adding a new alert if applicable.

        Args:
            record (dict): A parsed log with data.
            rule (RuleAttributes): Attributes for the rule which triggered the alert.
            payload (StreamPayload): Payload with information about the source of the record.
            alerts (list): The current list of Alert instances.
                If the rule returns True on the record, a new Alert instance is added to this list.
        """
        rule_result = rule.process(record)
        if not rule_result:
            return

        # when threat intel enabled, normalized records will be re-analyzed by
        # all rules. Thus we need to check duplication.
        if self._threat_intel and self.check_alerts_duplication(record, rule, alerts):
            return

        # Combine the required alert outputs with the ones for this rule
        all_outputs = self._required_outputs_set.union(rule.outputs_set)
        alert = Alert(
            rule.rule_name, record, all_outputs,
            cluster=os.environ['CLUSTER'],
            context=rule.context,
            log_source=str(payload.log_source),
            log_type=payload.type,
            merge_by_keys=rule.merge_by_keys,
            merge_window=timedelta(minutes=rule.merge_window_mins),
            rule_description=rule.description,
            source_entity=payload.entity,
            source_service=payload.service()
        )

        LOGGER.info('Rule [%s] triggered alert [%s] on log type [%s] from entity \'%s\' '
                    'in service \'%s\'', rule.rule_name, alert.alert_id, payload.log_source,
                    payload.entity, payload.service())

        alerts.append(alert)

    @staticmethod
    def _is_equal(record1, record2):
        """Check if two records are same excluding data normalization and threat intel information

        Compare key set before comparing values for better performance.

        Args:
            record1/record2 (dict): The parsed log w/wo data normalization and
            threat intel information.

        Returns:
            bool: Return True only when two records have same keys and values.
        """
        record1_keys = set(record1.keys()) - _IGNORE_KEYS
        record2_keys = set(record2.keys()) - _IGNORE_KEYS

        if record1_keys != record2_keys:
            return False

        return all(record1[key] == record2[key] for key in record1_keys)

    def check_alerts_duplication(self, record, rule, alerts):
        """ Check if the record has been triggerred an alert by the same rule

        The reason we need to do the duplication is because the record might be
        modified by inserting normalization or/and IOC information after data
        normalization. Threat Intel feature will re-analyze normalized records.

        Args:
            record (dict): A parsed log with data.
            rule: Rule attributes.
            alerts (list): A list of Alert instances which will be sent to alert processor.

        Returns:
            bool: Return True if both record and rule name exist in alerts list.
        """
        return any(self._is_equal(alert.record, record)
                   for alert in alerts
                   if rule.rule_name == alert.rule_name)

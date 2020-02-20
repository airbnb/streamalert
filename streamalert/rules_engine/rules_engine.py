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
from datetime import datetime, timedelta
from os import environ as env

from streamalert.shared.publisher import AlertPublisherRepository
from streamalert.rules_engine.alert_forwarder import AlertForwarder
from streamalert.rules_engine.threat_intel import ThreatIntel
from streamalert.shared import resources, RULES_ENGINE_FUNCTION_NAME as FUNCTION_NAME
from streamalert.shared.alert import Alert
from streamalert.shared.config import load_config
from streamalert.shared.importer import import_folders
from streamalert.shared.logger import get_logger
from streamalert.shared.lookup_tables.core import LookupTables
from streamalert.shared.metrics import MetricLogger
from streamalert.shared.rule import Rule
from streamalert.shared.rule_table import RuleTable
from streamalert.shared.stats import RuleStatisticTracker


LOGGER = get_logger(__name__)


class RulesEngine:
    """Rule engine to processes rules"""
    _RULE_TABLE_LAST_REFRESH = datetime(year=1970, month=1, day=1)
    _RULE_TABLE_DEFAULT_REFRESH_MIN = 10

    _config = None
    _lookup_tables = None
    _rule_table = None
    _threat_intel = None
    _alert_forwarder = None

    def __init__(self, *rule_paths):
        RulesEngine._config = RulesEngine._config or load_config()
        RulesEngine._threat_intel = (
            RulesEngine._threat_intel or ThreatIntel.load_from_config(self.config)
        )
        # Instantiate the alert forwarder to handle sending alerts to the alert processor
        RulesEngine._alert_forwarder = RulesEngine._alert_forwarder or AlertForwarder()

        # Load the lookup tables
        RulesEngine._lookup_tables = LookupTables.get_instance(config=self.config)

        # If no rule import paths are specified, default to the config
        rule_paths = rule_paths or [
            item for location in {'rule_locations', 'matcher_locations'}
            for item in self.config['global']['general'][location]
        ]

        import_folders(*rule_paths)

        self._rule_stat_tracker = RuleStatisticTracker(
            'STREAMALERT_TRACK_RULE_STATS' in env,
            'LAMBDA_RUNTIME_DIR' in env
        )
        self._required_outputs_set = resources.get_required_outputs()
        self._load_rule_table(self.config)

    @property
    def config(self):
        return RulesEngine._config

    @classmethod
    def get_lookup_table(cls, table_name):
        """Return lookup table by table name

        The rules engine supports to load arbitrary json files from S3 buckets into
        memory for quick reference while writing rules. This information is stored
        in class variable `_LOOKUP_TABLES` which is a dictionary. Json file name
        without extension will the key name(a.k.a table_name), and json content
        will be the value.

        Args:
            table_name (str): Lookup table name. It is also the json file name without
                extension.

        Returns:
            LookupTable: An instance of a LookupTable
        """
        return cls._lookup_tables.table(table_name)

    @classmethod
    def _load_rule_table(cls, config):
        """Load and return a RuleTable class for communicating with the DynamoDB rule table

        Args:
            config (dict): Loaded configuration from 'conf/' directory

        Returns:
            rule_table.RuleTable: Loaded frontend for DynamoDB rules table
        """
        # Ensure the rules table is enabled
        rule_staging_config = config['global']['infrastructure']['rule_staging']
        if not rule_staging_config.get('enabled', False):
            return

        now = datetime.utcnow()
        refresh_delta = timedelta(
            minutes=rule_staging_config.get(
                'cache_refresh_minutes',
                cls._RULE_TABLE_DEFAULT_REFRESH_MIN
            )
        )

        # The rule table will need 'refreshed' if the refresh interval has been surpassed
        needs_refresh = cls._RULE_TABLE_LAST_REFRESH + refresh_delta < now

        if not needs_refresh:
            LOGGER.debug('Rule table does not need refreshed (last refresh time: %s; '
                         'current time: %s)', cls._RULE_TABLE_LAST_REFRESH, now)
            return

        LOGGER.info('Refreshing rule table (last refresh time: %s; current time: %s)',
                    cls._RULE_TABLE_LAST_REFRESH, now)

        table_name = '{}_streamalert_rules'.format(env['STREAMALERT_PREFIX'])
        cls._rule_table = RuleTable(table_name)
        cls._RULE_TABLE_LAST_REFRESH = now

    @staticmethod
    def _process_subkeys(record, rule):
        """Determine if record contains all subkeys needed for rules

        This method verifies that the declared subkeys in a rule are contained
        in the dictionary prior to further rule processing.

        Args:
            record (dict): Record to perform subkey checking against
            rule (rule.Rule): Rule class with necessary attributes

        Returns:
            bool: result of subkey check.
        """
        if not rule.req_subkeys:
            return True

        for key, nested_keys in rule.req_subkeys.items():
            # This is an extra layer of protection when
            # verifying a subkey exists in a record with a null value.
            # In the case of CloudTrail, a top level key has been
            # observed as either a map with subkeys, or null.
            if key not in record:
                LOGGER.debug(
                    'The required subkey %s is not found when trying to process %s: \n%s',
                    key, rule.name, record)
                return False
            if not isinstance(record[key], dict):
                LOGGER.debug(
                    'The required subkey %s is not a dictionary when trying to process %s: \n%s',
                    key, rule.name, record)
                return False
            if any(x not in record[key] for x in nested_keys):
                return False

        return True

    def _extract_threat_intel(self, records):
        """Extract threat intelligence from records

        Args:
            records (list<dict>): A list of records for which to extract threat intel information
        """
        if not self._threat_intel:
            return

        self._threat_intel.threat_detection(records)

    def _rule_analysis(self, payload, rule):
        """Analyze a record with the rule, adding a new alert if applicable

        Args:
            payload (dict): Representation of event to perform rule analysis against
            rule (rule.Rule): Attributes for the rule which triggered the alert
        """
        # Run the rule, using the statistic tracker in case stats are being tracked
        rule_result = self._rule_stat_tracker.run_rule(rule, payload['record'])
        if not rule_result:
            return

        alert = Alert(
            rule.name, payload['record'], self._configure_outputs(rule),
            cluster=payload['cluster'],
            context=rule.context,
            log_source=payload['log_schema_type'],
            log_type=payload['data_type'],
            merge_by_keys=rule.merge_by_keys,
            merge_window=timedelta(minutes=rule.merge_window_mins),
            publishers=self._configure_publishers(rule),
            rule_description=rule.description,
            source_entity=payload['resource'],
            source_service=payload['service'],
            staged=rule.is_staged(self._rule_table)
        )

        LOGGER.info('Rule \'%s\' triggered alert \'%s\' on log type \'%s\' from resource \'%s\' '
                    'in service \'%s\'', rule.name, alert.alert_id, payload['log_schema_type'],
                    payload['resource'], payload['service'])

        return alert

    def _configure_outputs(self, rule):
        # Check if the rule is staged and, if so, only use the required alert outputs
        if rule.is_staged(self._rule_table):
            all_outputs = self._required_outputs_set
        else:  # Otherwise, combine the required alert outputs with the ones for this rule
            all_outputs = self._required_outputs_set.union(rule.outputs_set)

        return all_outputs

    @classmethod
    def _configure_publishers(cls, rule):
        """Assigns publishers to each output.

        The @Rule publisher syntax accepts several formats, including a more permissive blanket
        option.

        In this configuration we DELIBERATELY do not include required_outputs as required outputs
        should never have their alerts transformed.

        Args:
            rule (Rule): The rule to create publishers for

        Returns:
            dict: Maps string outputs names to lists of strings of their fully qualified publishers
        """
        requested_outputs = rule.outputs_set
        requested_publishers = rule.publishers
        if not requested_publishers:
            return None

        configured_publishers = {}

        for output in requested_outputs:
            assigned_publishers = []

            if cls.is_publisher_declaration(requested_publishers):
                # Case 1: The publisher is a single string.
                #   apply this single publisher to all outputs + descriptors
                cls.add_publisher(requested_publishers, assigned_publishers)
            elif isinstance(requested_publishers, list):
                # Case 2: The publisher is an array of strings.
                #   apply all publishers to all outputs + descriptors
                cls.add_publishers(requested_publishers, assigned_publishers)
            elif isinstance(requested_publishers, dict):
                # Case 3: The publisher is a dict mapping output strings -> strings or list of
                #   strings. Apply only publishers under a matching output key.
                #
                #   We look under 2 keys:
                #     - [Output]: Applies publishers to all outputs for a specific output type.
                #     - [Output+Descriptor]: Applies publishers only to the specific output that
                #           exactly matches the output+descriptor key.
                output_service = output.split(':')[0]

                # Order is important here; We load output-specific publishers first
                if output_service in requested_publishers:
                    specific_publishers = requested_publishers[output_service]
                    if cls.is_publisher_declaration(specific_publishers):
                        cls.add_publisher(specific_publishers, assigned_publishers)
                    elif isinstance(specific_publishers, list):
                        cls.add_publishers(specific_publishers, assigned_publishers)

                # Then we load the output+descriptor-specific publishers second
                if output in requested_publishers:
                    specific_publishers = requested_publishers[output]
                    if cls.is_publisher_declaration(specific_publishers):
                        cls.add_publisher(specific_publishers, assigned_publishers)
                    elif isinstance(specific_publishers, list):
                        cls.add_publishers(specific_publishers, assigned_publishers)
            else:
                LOGGER.error('Invalid publisher argument: %s', requested_publishers)

            configured_publishers[output] = assigned_publishers

        return configured_publishers

    @classmethod
    def standardize_publisher_list(cls, list_of_references):
        """Standardizes a list of requested publishers"""
        publisher_names = [cls.standardize_publisher_name(x) for x in list_of_references]

        # Filter out None from the array
        return [x for x in publisher_names if x is not None]

    @classmethod
    def standardize_publisher_name(cls, string_or_reference):
        """Standardizes a requested publisher into a string name

        Requested publishers can be either the fully qualified string name, OR it can be a
        direct reference to the function or class.
        """
        if not cls.is_publisher_declaration(string_or_reference):
            LOGGER.error('Invalid publisher requested: %s', string_or_reference)
            return None

        if isinstance(string_or_reference, str):
            publisher_name = string_or_reference
        else:
            publisher_name = AlertPublisherRepository.get_publisher_name(
                string_or_reference
            )

        if AlertPublisherRepository.has_publisher(publisher_name):
            return publisher_name

        LOGGER.warning('Requested publisher named (%s) is not registered.', publisher_name)

    @classmethod
    def is_publisher_declaration(cls, string_or_reference):
        """Returns TRUE if the requested publisher is valid (a string name or reference)"""
        return (
            isinstance(string_or_reference, str) or
            AlertPublisherRepository.is_valid_publisher(string_or_reference)
        )

    @classmethod
    def add_publisher(cls, publisher_reference, current_list):
        _publisher = cls.standardize_publisher_name(publisher_reference)
        current_list += [_publisher] if _publisher is not None else []

    @classmethod
    def add_publishers(cls, publisher_references, current_list):
        current_list += cls.standardize_publisher_list(publisher_references)

    def run(self, records):
        """Run rules against the records sent from the Classifier function

        Args:
            records (list): Dictionaries of records sent from the classifier function
                Record Format:
                    {
                        'cluster': 'prod',
                        'log_schema_type': 'cloudwatch:cloudtrail',
                        'record': {
                            'key': 'value'
                        },
                        'service': 'kinesis',
                        'resource': 'kinesis_stream_name'
                        'data_type': 'json'
                    }

        Returns:
            list: Alerts that have been triggered by this data
        """
        LOGGER.info('Processing %d records', len(records))

        # Extract any threat intelligence matches from the records
        self._extract_threat_intel(records)

        alerts = []
        for payload in records:
            rules = Rule.rules_for_log_type(payload['log_schema_type'])
            if not rules:
                LOGGER.debug('No rules to process for %s', payload)
                continue

            for rule in rules:
                # subkey check
                if not self._process_subkeys(payload['record'], rule):
                    continue

                # matcher check
                if not rule.check_matchers(payload['record']):
                    continue

                alert = self._rule_analysis(payload, rule)
                if alert:
                    alerts.append(alert)

        self._alert_forwarder.send_alerts(alerts)

        # Only log rule info here if this is deployed in Lambda or explicitly enabled
        # During testing, this gets logged at the very end
        if self._rule_stat_tracker.enabled:
            LOGGER.info(RuleStatisticTracker.statistics_info())

        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.TRIGGERED_ALERTS, len(alerts))

        return alerts

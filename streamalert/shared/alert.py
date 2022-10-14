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
import json
import uuid
from datetime import datetime, timedelta

from streamalert.shared import resources, utils


class AlertCreationError(Exception):
    """Raised when alert creation fails because of an invalid format."""


class Alert:
    """Encapsulates a single alert and handles serializing to Dynamo and merging."""

    _EXPECTED_INIT_KWARGS = {
        'alert_id', 'attempts', 'cluster', 'context', 'created', 'dispatched', 'log_source',
        'log_type', 'merge_by_keys', 'merge_window', 'outputs_sent', 'publishers',
        'rule_description', 'source_entity', 'source_service', 'staged'
    }
    DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

    def __init__(self, rule_name, record, outputs, **kwargs):
        """Create a new Alert with a random ID and timestamped now.

        Args:
            rule_name (str): Name of the rule which triggered the alert
            record (dict): Parsed log which triggered the alert
            outputs (set): Set of string outputs where the alert should be delivered to

        Kwargs (optional):
            alert_id (str): Existing AlertID, if known. If not specified, a random one is created.
            attempts (int): Number of attempts to deliver this alert so far. Defaults to 0.
            cluster (str): Cluster from which the alert was generated.
            context (dict): Context dictionary associated with the triggering rule.
            created (datetime): Alert creation time (UTC).
            dispatched (datetime): Time alert was last dispatched (UTC).
            log_source (str): Log type which triggered the alert, e.g. "binaryalert"
            log_type (str): The type of the triggering log. Usually "json"
            merge_by_keys (list): Alerts are merged if the values associated with all of these
                keys are equal. Keys can be present at any depth in the record.
            merge_window (timedelta): Merged alerts are sent at this interval.
            outputs_sent (set): Subset of outputs which have sent successfully.
            publishers (str|list|dict): A structure of Strings, representing either fully qualified
                function names, or publisher classes. Adopts one of the following formats:

                - None, or empty array; DefaultPublisher is run on all outputs.
                - Single string; One publisher is run on all outputs.
                - List of strings; All publishers are run on all outputs in order of declaration.
                - Dict mapping to strings or lists: The dict maps output service keys to a string
                    or lists of strings. These strings corresponds to all publishers that are run,
                    in order, for only that specific output service.

            rule_description (str): Description associated with the triggering rule.
            source_entity (str): Name of location from which the record originated. E.g. "mychannel"
            source_service (str): Input type from which the record originated. E.g. "slack"
            staged (bool): Whether this rule is currently in the staging process. Defaults to False

        Raises:
            AlertCreationError: If the keyword arguments are not in the expected set.
        """
        if not set(kwargs).issubset(self._EXPECTED_INIT_KWARGS):
            raise AlertCreationError(
                f"Invalid Alert kwargs: {', '.join(sorted(set(kwargs).difference(self._EXPECTED_INIT_KWARGS)))} "
                f"are not in the expected set of {', '.join(sorted(self._EXPECTED_INIT_KWARGS))}")

        # Empty strings and empty sets are not allowed in Dynamo, so for safety we explicitly
        # convert any Falsey value to the expected type during Alert creation.
        # This is why we use "or" instead of kwargs.get() with a default value.
        self.alert_id = kwargs.get('alert_id') or str(uuid.uuid4())
        self.created = kwargs.get('created') or datetime.utcnow()

        self.outputs = outputs
        self.record = record
        self.rule_name = rule_name

        self.attempts = int(kwargs.get('attempts', 0)) or 0  # Convert possible Decimal to int
        self.cluster = kwargs.get('cluster') or None
        self.context = kwargs.get('context') or {}
        self.publishers = kwargs.get('publishers') or {}

        # datetime.min isn't supported by strftime, so use Unix epoch instead for default value
        self.dispatched = kwargs.get('dispatched') or datetime(year=1970, month=1, day=1)

        self.log_source = kwargs.get('log_source') or None
        self.log_type = kwargs.get('log_type') or None
        self.merge_by_keys = kwargs.get('merge_by_keys') or []
        self.merge_window = kwargs.get('merge_window') or timedelta(minutes=0)
        self.outputs_sent = kwargs.get('outputs_sent') or set()
        self.rule_description = kwargs.get('rule_description') or None
        self.source_entity = kwargs.get('source_entity') or None
        self.source_service = kwargs.get('source_service') or None
        self.staged = kwargs.get('staged') or False

    def __lt__(self, other):
        """Alerts are ordered by their creation time."""
        return self.created < other.created

    def __repr__(self):
        """Complete representation (for debugging) is an indented JSON string with all fields."""
        return json.dumps(self.dynamo_record(), default=list, indent=2, sort_keys=True)

    def __str__(self):
        """Simple string representation includes alert ID and triggered rule."""
        return f'<Alert {self.alert_id} triggered from {self.rule_name}>'

    @property
    def dynamo_key(self):
        """Key (dict) used to lookup this alert in the alerts table."""
        return {'RuleName': self.rule_name, 'AlertID': self.alert_id}

    @property
    def merge_enabled(self):
        """Return True if merge configuration is enabled for this alert."""
        return self.merge_by_keys and self.merge_window

    @property
    def remaining_outputs(self):
        """Return the set of outputs which still need to be sent for this alert."""
        if self.merge_enabled:
            # This alert will be merged later - for now, we care only about required outputs.
            outputs_to_send_now = self.outputs.intersection(resources.get_required_outputs())
        else:
            outputs_to_send_now = self.outputs
        return outputs_to_send_now.difference(self.outputs_sent)

    def dynamo_record(self):
        """Convert this alert to a complete Dynamo record for the alerts table.

        Returns:
            dict: Dynamo-compatible dictionary with all alert fields
        """
        return {
            'RuleName': self.rule_name,  # Partition Key
            'AlertID': self.alert_id,  # Sort/Range Key
            'Attempts': self.attempts,
            'Cluster': self.cluster,
            'Context': self.context,
            'Created': self.created.strftime(self.DATETIME_FORMAT),
            'Dispatched': self.dispatched.strftime(self.DATETIME_FORMAT),
            'LogSource': self.log_source,
            'LogType': self.log_type,
            'MergeByKeys': self.merge_by_keys,
            'MergeWindowMins': int(self.merge_window.total_seconds() / 60),
            'Outputs': self.outputs,
            'OutputsSent': self.outputs_sent or None,  # Empty sets not allowed by Dynamo
            'Publishers': self.publishers or None,
            # Compact JSON encoding (no spaces). We have to JSON-encode here
            # (instead of just passing the dict) because Dynamo does not allow empty string values.
            'Record': json.dumps(self.record, separators=(',', ':'), default=list),
            'RuleDescription': self.rule_description,
            'SourceEntity': self.source_entity,
            'SourceService': self.source_service,
            'Staged': self.staged
        }

    @classmethod
    def create_from_dynamo_record(cls, record):
        """Transform a Dynamo record back into an Alert.

        Args:
            record (dict): Dynamo item corresponding to a single alert

        Returns:
            Alert: An alert with all properties populated from the Dynamo item

        Raises:
            AlertCreationError: If the record isn't formatted correctly.
        """
        try:
            return cls(
                record['RuleName'],
                json.loads(record['Record']),
                set(record['Outputs']),  # In JSON, outputs may be a list - convert back to set
                alert_id=record['AlertID'],
                attempts=record.get('Attempts'),
                cluster=record.get('Cluster'),
                context=record.get('Context'),
                created=datetime.strptime(record['Created'], cls.DATETIME_FORMAT),
                dispatched=datetime.strptime(record['Dispatched'], cls.DATETIME_FORMAT)
                if 'Dispatched' in record else None,
                log_source=record.get('LogSource'),
                log_type=record.get('LogType'),
                merge_by_keys=record.get('MergeByKeys'),
                merge_window=timedelta(minutes=int(record.get('MergeWindowMins', 0))),
                outputs_sent=set(record.get('OutputsSent') or []),
                publishers=record.get('Publishers'),
                rule_description=record.get('RuleDescription'),
                source_entity=record.get('SourceEntity'),
                source_service=record.get('SourceService'),
                staged=record.get('Staged'))
        except (KeyError, TypeError, ValueError) as error:
            raise AlertCreationError(error) from error

    def output_dict(self):
        """Convert the alert into a dictionary ready to send to an output.

        (!) This method is deprecated. Going forward, try to use the method:

            streamalert.alert_processor.helpers.compose_alert

        Returns:
            dict: An alert dictionary for sending to outputs.
                The result is JSON-compatible, backwards-compatible (existing keys are not changed),
                and Athena-compatible (empty strings are used instead of None for top-level values).
        """
        # As a general rule, new keys may be added but existing keys should not be changed.
        # This way, output consumers looking for specific alert keys will still find them.
        # For example, historical search in Athena may break if these keys are renamed.
        return {
            'cluster': self.cluster or '',
            'context': self.context or {},
            'created': self.created.strftime(self.DATETIME_FORMAT),
            'id': self.alert_id,
            'log_source': self.log_source or '',
            'log_type': self.log_type or '',
            'outputs': sorted(self.outputs),  # List instead of set for JSON-compatibility
            'publishers': self.publishers or {},
            'record': self.record,
            'rule_description': self.rule_description or '',
            'rule_name': self.rule_name or '',
            'source_entity': self.source_entity or '',
            'source_service': self.source_service or '',
            'staged': self.staged,
        }

    # ---------- Alert Merging ----------

    def can_merge(self, other):
        """Check if two alerts can be merged together.

        Args:
            other (Alert): Check if the instance can merge with this other alert.

        Returns:
            True if these alerts fit in the same merge window and have the same merge key values.
        """
        if not self.merge_enabled or not other.merge_enabled:
            # Merge information is not defined for both of these alerts.
            return False

        older, newer = min(self, other), max(self, other)
        if newer.created > older.created + older.merge_window:
            # These alerts won't fit in a single merge window.
            return False

        if set(self.merge_by_keys) != set(other.merge_by_keys):
            # These alerts have different definitions of merge keys.
            return False

        return all(
            utils.get_first_key(self.record, key) == utils.get_first_key(other.record, key)
            for key in self.merge_by_keys)

    @classmethod
    def _clean_record(cls, record, ignored_keys):
        """Remove ignored keys from every level of the record.

        Args:
            record (dict): Record to traverse
            ignored_keys (set): Set of keys to remove from the record

        Returns:
            dict: A new record, with no ignored_keys
        """
        return {
            key: cls._clean_record(val, ignored_keys) if isinstance(val, dict) else val
            for key, val in record.items() if key not in ignored_keys
        }

    @classmethod
    def _compute_common(cls, records):
        """Find values common to every record.

        Args:
            records (list): List of record dictionaries.

        Returns:
            dict: The greatest common subset of all records.

        Example:
            _compute_common([
                {'abc': 123, 'nested': {'A': 1, 'B': 2}},
                {'abc': 123, 'def': 456, 'nested': {'A': 1}}
            ])
            will return {'abc': 123, 'nested': {'A': 1}}
        """
        if not records:
            return {}
        if len(records) == 1:
            return records[0]

        # Any common key must be in the first record, so just traverse the first record.
        other_records = records[1:]
        common = {}
        for key, val in records[0].items():
            if any(key not in r for r in other_records):
                # This key does not exist in all other records and so cannot be common.
                continue

            if all(r[key] == val for r in other_records):
                # Every other record has the same key:value pair - add it to the common results.
                # This also works for identical nested structures, avoiding unnecessary recursion.
                common[key] = val
                continue

            if isinstance(val, dict):
                # This nested dict is not completely common to all records, but maybe some of it is.

                if not all(isinstance(r[key], dict) for r in other_records):
                    # This key is not a dictionary in every record - no partial similarities exist.
                    continue

                if nested_common := cls._compute_common([r[key] for r in records]):
                    common[key] = nested_common

        return common

    @classmethod
    def _compute_diff(cls, common, record):
        """Find values in the given record that are not in the common subset.

        Args:
            common (dict): Common features from _compute_common
            record (dict): Individual record

        Returns:
            dict: The record subset whose values differ from the common ones.

        Example:
            _compute_diffs(
                {'abc': 123, 'nested': {'A': 1}},  # common
                {'abc': 123, 'nested': {'A': 1, 'B': 2}  # record
            )
            will return {'nested': {'B': 2}}
        """
        if not common:
            return record

        diff = {}
        for key, val in record.items():
            if key not in common:
                # This key is in the record but not in the common set.
                # Everything in the value is unique to this record.
                diff[key] = val
                continue

            if val == common[key]:
                # The record value is identical to the common value - no diffs here.
                continue

            if isinstance(val, dict) and isinstance(common[key], dict):
                if inner_diff := cls._compute_diff(common[key], val):
                    diff[key] = inner_diff
            else:
                # No recursion necessary - this value is definitely not in common.
                diff[key] = val

        return diff

    @classmethod
    def merge(cls, alerts):
        """Combine a list of alerts into a new merged alert.

        The caller is responsible for determining *which* alerts should be merged, this just
        implements the merge algorithm.

        Args:
            alerts (list): List of alerts to merge.
                These should all have the same values for their merge keys.

        Returns:
            Alert: A new alert whose record is formed by merging the records of all the alerts.
                The merged alert outputs are a union of all outputs in the original alerts.
                Other information (rule name, description, etc) is copied from the first alert.
        """
        alerts = sorted(alerts)  # Put alerts in chronological order.
        merge_keys = set(alerts[0].merge_by_keys)
        # Remove merge keys from the alert record, so that it doesn't show up in common/diff
        records = [cls._clean_record(alert.record, merge_keys) for alert in alerts]
        common = cls._compute_common(records)

        # Keys are named such that more important information is at the beginning alphabetically.
        new_record = {
            'AlertCount': len(alerts),
            'AlertTimeFirst': min(alert.created for alert in alerts).strftime(cls.DATETIME_FORMAT),
            'AlertTimeLast': max(alert.created for alert in alerts).strftime(cls.DATETIME_FORMAT),
            'MergedBy':
            {key: utils.get_first_key(alerts[0].record, key, '(n/a)')
             for key in merge_keys},
            'OtherCommonKeys': common,
            'ValueDiffs': {
                alert.created.strftime(cls.DATETIME_FORMAT): cls._compute_diff(common, record)
                for alert, record in zip(alerts, records)
            }
        }

        # TODO: the cluster, log_source, source_entity, etc, could be different between alerts
        return cls(
            alerts[0].rule_name,
            new_record,
            alerts[-1].outputs,  # Use the most recent set of outputs
            cluster=alerts[0].cluster,
            context=alerts[0].context,
            log_source=alerts[0].log_source,
            log_type=alerts[0].log_type,
            publishers=alerts[0].publishers,
            rule_description=alerts[0].rule_description,
            source_entity=alerts[0].source_entity,
            source_service=alerts[0].source_service,
            staged=any(alert.staged for alert in alerts))

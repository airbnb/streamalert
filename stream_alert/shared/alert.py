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
from datetime import datetime
import json
import uuid


class Alert(object):
    """Encapsulates a single alert and handles serializing to Dynamo and merging."""

    class AlertEncoder(json.JSONEncoder):
        """Custom JSON encoder which handles sets."""
        def default(self, obj):  # pylint: disable=arguments-differ,method-hidden
            if isinstance(obj, set):
                return list(obj)
            return json.JSONEncoder.default(self, obj)

    _EXPECTED_INIT_KWARGS = {
        'alert_id', 'attempts', 'cluster', 'context', 'created', 'dispatched', 'log_source',
        'log_type', 'merge_by_keys', 'merge_window_mins', 'retry_outputs', 'rule_description',
        'source_entity', 'source_service', 'staged'
    }

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
            created (str): Human-readable creation timestamp. If not specified, uses current time.
            dispatched (int): UNIX timestamp when the alert was last dispatched for processing.
            log_source (str): Log type which triggered the alert, e.g. "binaryalert"
            log_type (str): The type of the triggering log. Usually "json"
            merge_by_keys (list): Alerts are merged if the values associated with all of these
                top-level keys are equal. TODO: Support nested merge keys
            merge_window_mins (int): Merged alerts are sent at this interval.
            retry_outputs (set): Subset of outputs which failed to send and should be retried.
            rule_description (str): Description associated with the triggering rule.
            source_entity (str): Name of location from which the record originated. E.g. "mychannel"
            source_service (str): Input type from which the record originated. E.g. "slack"
            staged (bool): Whether this rule is currently in the staging process. Defaults to False
        """
        if not set(kwargs).issubset(self._EXPECTED_INIT_KWARGS):
            raise TypeError(
                'Invalid Alert kwargs: {} is not a subset of {}'.format(
                    ','.join(sorted(kwargs)), ','.join(sorted(self._EXPECTED_INIT_KWARGS))
                )
            )

        self.alert_id = kwargs.get('alert_id') or str(uuid.uuid4())
        self.created = kwargs.get('created') or datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        self.outputs = outputs
        self.record = record
        self.rule_name = rule_name

        # Empty strings and empty sets are not allowed in Dynamo, so we explicitly convert to None
        self.attempts = int(kwargs.get('attempts', 0)) or 0  # Convert possible Decimal to int
        self.cluster = kwargs.get('cluster') or None
        self.context = kwargs.get('context') or {}
        self.dispatched = int(kwargs.get('dispatched', 0)) or 0
        self.log_source = kwargs.get('log_source') or None
        self.log_type = kwargs.get('log_type') or None
        self.merge_by_keys = kwargs.get('merge_by_keys') or []
        self.merge_window_mins = int(kwargs.get('merge_window_mins', 0)) or 0
        self.retry_outputs = kwargs.get('retry_outputs') or None
        self.rule_description = kwargs.get('rule_description') or None
        self.source_entity = kwargs.get('source_entity') or None
        self.source_service = kwargs.get('source_service') or None
        self.staged = kwargs.get('staged') or False

    def __lt__(self, other):
        """Alerts are ordered by their creation time."""
        return self.created < other.created

    def __repr__(self):
        """Complete representation (for debugging) is an indented JSON string with all fields."""
        return json.dumps(self.dynamo_record(), cls=self.AlertEncoder, indent=4, sort_keys=True)

    def __str__(self):
        """Simple string representation includes alert ID and triggered rule."""
        return '<Alert {} triggered from {}>'.format(self.alert_id, self.rule_name)

    @property
    def dynamo_key(self):
        """Key (dict) used to lookup this alert in the alerts table."""
        return {'RuleName': self.rule_name, 'AlertID': self.alert_id}

    @property
    def remaining_outputs(self):
        """Return the set of outputs which still need to be sent."""
        return self.retry_outputs or self.outputs

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
            'Created': self.created,
            'Dispatched': self.dispatched,
            'LogSource': self.log_source,
            'LogType': self.log_type,
            'MergeByKeys': self.merge_by_keys,
            'MergeWindowMins': self.merge_window_mins,
            'Outputs': self.outputs,
            # Compact JSON encoding (no spaces). We have to JSON-encode here
            # (instead of just passing the dict) because Dynamo does not allow empty string values.
            'Record': json.dumps(self.record, separators=(',', ':')),
            'RetryOutputs': self.retry_outputs,
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
        """
        return cls(
            record['RuleName'],
            json.loads(record['Record']),
            record['Outputs'],
            alert_id=record['AlertID'],
            attempts=record.get('Attempts'),
            cluster=record.get('Cluster'),
            context=record.get('Context'),
            created=record.get('Created'),
            dispatched=record.get('Dispatched'),
            log_source=record.get('LogSource'),
            log_type=record.get('LogType'),
            merge_by_keys=record.get('MergeByKeys'),
            merge_window_mins=record.get('MergeWindowMins'),
            retry_outputs=record.get('RetryOutputs'),
            rule_description=record.get('RuleDescription'),
            source_entity=record.get('SourceEntity'),
            source_service=record.get('SourceService'),
            staged=record.get('Staged')
        )

    def output_dict(self):
        """Convert the alert into a dictionary ready to send to an output.

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
            'created': self.created or '',
            'id': self.alert_id,
            'log_source': self.log_source or '',
            'log_type': self.log_type or '',
            'outputs': list(sorted(self.outputs)),  # List instead of set for JSON-compatibility
            'record': self.record,
            'rule_description': self.rule_description or '',
            'rule_name': self.rule_name or '',
            'source_entity': self.source_entity or '',
            'source_service': self.source_service or '',
            'staged': self.staged
        }

    # ---------- Alert Merging ----------

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
        for key, val in records[0].iteritems():
            if not all(key in r for r in other_records):
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

                nested_common = cls._compute_common([r[key] for r in records])
                if nested_common:
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
        for key, val in record.iteritems():
            if key not in common:
                # This key is in the record but not in the common set.
                # Everything in the value is unique to this record.
                diff[key] = val
                continue

            if val == common[key]:
                # The record value is identical to the common value - no diffs here.
                continue

            if isinstance(val, dict) and isinstance(common[key], dict):
                # The value is a dict which is not entirely in common, but maybe partially so.
                inner_diff = cls._compute_diff(common[key], val)
                if inner_diff:
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
        common = cls._compute_common([alert.record for alert in alerts])
        merged_by = {key: common[key] for key in alerts[0].merge_by_keys}

        # Keys are named such that more important information is at the beginning alphabetically.
        new_record = {
            'AlertCount': len(alerts),
            'AlertTimeFirst': min(alert.created for alert in alerts),
            'AlertTimeLast': max(alert.created for alert in alerts),
            'MergedBy': merged_by,
            'OtherCommonKeys': {k: v for k, v in common.iteritems() if k not in merged_by},
            'ValueDiffs': [cls._compute_diff(common, alert.record) for alert in alerts]
        }

        # Union all of the outputs together.
        all_outputs = set()
        for alert in alerts:
            all_outputs.update(alert.outputs)

        # TODO: the cluster, log_source, source_entity, etc, could be different between alerts
        return cls(
            alerts[0].rule_name,
            new_record,
            all_outputs,
            cluster=alerts[0].cluster,
            context=alerts[0].context,
            log_source=alerts[0].log_source,
            log_type=alerts[0].log_type,
            rule_description=alerts[0].rule_description,
            source_entity=alerts[0].source_entity,
            source_service=alerts[0].source_service,
            staged=any(alert.staged for alert in alerts)
        )

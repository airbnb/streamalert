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
from datetime import datetime, timedelta

import boto3

from stream_alert.shared import LOGGER
from stream_alert.shared.rule import import_folders, Rule


class RuleTable(object):
    """Provides convenience methods for accessing and modifying the rules table."""
    DEFAULT_STAGING_HOURS = 48
    DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

    def __init__(self, table_name, *rule_import_paths):
        """Load the given table to be used for rule information updates

        Args:
            rule_import_paths (string): Variable number of paths to import rules
                from. Useful for using this as a standalone class. Items for this
                can be ommitted if instantiated from a caller that has already
                loaded the rules files.
        """
        self._table = boto3.resource('dynamodb').Table(table_name)
        import_folders(*rule_import_paths)
        self._remote_rule_info = None

    def __str__(self, verbose=False):
        """Return a human-readable respresentation of the table's data"""
        if not self.remote_rule_names:
            return 'Rule table is empty'

        pad_size = max([len(rule) for rule in self.remote_rule_info.keys()]) + 4
        output = ['{rule:<{pad}}Staged?'.format(rule='Rule', pad=pad_size+5)]
        for index, rule in enumerate(sorted(self.remote_rule_info.keys()), start=1):
            output.append(
                '{index:>3d}: {rule: <{pad}}{staged}'.format(
                    index=index,
                    rule=rule,
                    pad=pad_size,
                    staged=self.remote_rule_info[rule]['Staged']
                )
            )
            # Append additional information if verbose is enabled
            if verbose:
                details_pad_size = max([len(prop)
                                        for prop in self.remote_rule_info[rule].keys()]) + 4
                output.extend(
                    '{prefix:>{left_pad}}{property: <{internal_pad}}{value}'.format(
                        prefix='- ',
                        left_pad=7,
                        property='{}:'.format(prop),
                        internal_pad=details_pad_size,
                        value=value
                    )
                    for prop, value in self.remote_rule_info[rule].iteritems()
                    if prop != 'Staged'
                )

        return '\n'.join(output)

    def _add_new_rules(self):
        """Add any new local rules (renamed rules included) to the remote database"""
        # If the table is empty, no rules have been added yet
        # Add them all as unstaged to avoid demoting rules from production status
        init = (len(self.remote_rule_names) == 0)
        with self._table.batch_writer() as batch:
            for rule_name in self.local_not_remote:
                LOGGER.debug('Adding rule \'%s\' (init=%s)', rule_name, init)
                batch.put_item(self._dynamo_record(rule_name, init))

    def _del_old_rules(self):
        """Delete any rules that exist in the rule database but not locally"""
        with self._table.batch_writer() as batch:
            for rule_name in self.remote_not_local:
                LOGGER.debug('Deleting rule \'%s\'', rule_name)
                batch.delete_item(Key={'RuleName': rule_name})

    def _load_remote_state(self):
        """Return the state of all rules stored in the database

        Returns:
            dict: key = rule name, value = dictionary of staging information
                Example:
                    {
                        'example_rule_name':
                            {
                                'Staged': True
                                'StagedAt': '2018-04-19T02:23:13.332223Z',
                                'NewlyStaged': True,
                                'StagedUntil': '2018-04-21T02:23:13.332223Z'
                            }
                    }
        """
        paginator = self._table.meta.client.get_paginator('scan')
        page_iterator = paginator.paginate(TableName=self.name, ConsistentRead=True)
        return {
            item['RuleName']: {
                key: value for key, value in item.iteritems()
                if key != 'RuleName'
            }
            for page in page_iterator
            for item in page['Items']
        }

    @staticmethod
    def _dynamo_record(rule_name, init=False):
        """Generate a DynamoDB record with this rule information

        Args:
            rule_name (string): Name of rule for this record
            init (bool): [optional] argument that dictates if this is an initial
                deploy of rule info to the rules table. Initial deployment of rule
                info will skip the staging state as to avoid taking rules out of
                production unexpectedly.
        """
        item = {
            'RuleName': rule_name,
            'Staged': not init
        }

        # If the database is empty (ie: newly created), do not stage existing rules
        if init:
            return item

        staged_at, staged_until = RuleTable._staged_window()
        item.update({
            'StagedAt': staged_at,
            'StagedUntil': staged_until,
            'NewlyStaged': True
        })

        return item

    @staticmethod
    def _staged_window():
        """Get staging window to be used for this rule

        Returns:
            tuple: staging start datetime, staging end datetime
        """
        staged_at = datetime.utcnow()
        staged_until = staged_at + timedelta(hours=RuleTable.DEFAULT_STAGING_HOURS)
        return (
            staged_at.strftime(RuleTable.DATETIME_FORMAT),
            staged_until.strftime(RuleTable.DATETIME_FORMAT)
        )

    def update(self):
        """Update the database with new local rules and remove deleted ones from remote"""
        self._add_new_rules()
        self._del_old_rules()

    @property
    def local_not_remote(self):
        """Rules that exist locally but not within the remote database"""
        return self.local_rule_names.difference(self.remote_rule_names)

    @property
    def local_rule_names(self):
        """Names of locally loaded rules"""
        return set(Rule.rule_names())

    @property
    def name(self):
        """Name of the DynamoDB table used to store alerts."""
        return self._table.table_name

    @property
    def remote_rule_info(self):
        """All rule info from the remote database. Returns cache if it exists"""
        if not self._remote_rule_info:
            self._remote_rule_info = self._load_remote_state()
        return self._remote_rule_info

    @property
    def remote_rule_names(self):
        """Rule names from the remote database. Returns cache if it exists"""
        if not self._remote_rule_info:
            self._remote_rule_info = self._load_remote_state()
        return set(self._remote_rule_info)

    @property
    def remote_not_local(self):
        """Rules that exist in the remote database but not locally"""
        return self.remote_rule_names.difference(self.local_rule_names)

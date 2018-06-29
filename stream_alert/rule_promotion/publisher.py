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
import json

import boto3

from stream_alert.rule_promotion import LOGGER


class StatsPublisher(object):
    """Run queries to generate statistics on alerts."""

    DEFAULT_STATS_SNS_TOPIC = 'staging_stats'
    SSM_STATE_NAME = 'staging_stats_publisher_state'
    SSM_CLIENT = None

    def __init__(self, config, athena_client, current_time):
        self._topic_arn = self.formatted_sns_topic_arn(config)
        self._athena_client = athena_client
        self._current_time = current_time
        self._state = self._load_state()

    @classmethod
    def formatted_sns_topic_arn(cls, config):
        """Format the sns topic into and aws ARN

        Args:
            config: Loaded config from conf/ containing user defined topic (if available)

        Return:
            str: Formatted SNS topic arn using either the config option or default topic
        """
        topic = config['lambda']['rule_promotion_config'].get(
            'digest_sns_topic',
            cls.DEFAULT_STATS_SNS_TOPIC
        )
        return 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
            region=config['global']['account']['region'],
            account_id=config['global']['account']['aws_account_id'],
            topic=topic
        )

    @staticmethod
    def _format_digest(stats):
        """Sort and format the alert statistics info

        Args:
            stats (list<StagingStatistic>): Group of rule staging statistics
                that are being reported on

        Returns:
            str: Entire message digest to be sent to SNS, sorted with statistics
                that have the highest alert count at the top
        """
        if not stats:
            return 'No currently staged rules to report on'

        return '\n\n'.join(str(stat) for stat in sorted(stats, reverse=True))

    @classmethod
    def _load_state(cls):
        """Retrieve the remote state configuration from systems manager

        Returns:
            dict: The JSON configuration loaded into a dictionary
        """
        cls.SSM_CLIENT = boto3.client('ssm')
        response = cls.SSM_CLIENT.get_parameter(Name=cls.SSM_STATE_NAME)
        return json.loads(response['Parameter']['Value'])

    def _write_state(self):
        """Write the new state configuration to systems manager"""
        self._state['sent_daily_digest'] = (
            self._state['send_digest_hour_utc'] == self._current_time.hour
        )
        param_value = json.dumps(self._state)
        StatsPublisher.SSM_CLIENT.put_parameter(
            Name=self.SSM_STATE_NAME,
            Value=param_value,
            Overwrite=True
        )

    def _query_alerts(self, stat):
        """Execute a query for all alerts for a rule so the user can be sent the results

        Args:
            rule_name (str): Name of the rule to query for alert results

        Returns:
            str: Execution ID for running Athena query
        """
        # If there are no alerts, do not run the comprehensive query
        if not stat.alert_count:
            return

        info_statement = stat.sql_info_statement
        LOGGER.debug('Querying alert info for rule \'%s\': %s', stat.rule_name, info_statement)

        response = self._athena_client.run_async_query(info_statement)
        if not response:
            LOGGER.error('Failed to query alert info for rule: \'%s\'', stat.rule_name)
            return

        return response['QueryExecutionId']

    def _publish_message(self, stats):
        """Publish the alert statistics message to SNS

        Args:
            stats (list<StagingStatistic>): Group of rule staging statistics
                that are being reported on
        """
        LOGGER.info('Sending daily message digest at %s', self._current_time)

        sns_client = boto3.resource('sns').Topic(self._topic_arn)

        subject = 'Alert statistics for {} staged rule(s) [{} UTC]'.format(
            len(stats),
            self._current_time
        )

        sns_client.publish(
            Message=self._format_digest(stats),
            Subject=subject
        )

    @property
    def _should_send_digest(self):
        """Returns True if the daily digest should be sent, False otherwise"""
        return (
            self._state['send_digest_hour_utc'] == self._current_time.hour
            and not self._state.get('sent_daily_digest')
        )

    def publish(self, stats):
        """Public method for publishing alert statistics message to SNS

        Args:
            stats (list<StagingStatistic>): Group of rule staging statistics
                that are being reported on
        """
        if self._should_send_digest:

            for stat in stats:
                stat.execution_id = self._query_alerts(stat)

            self._publish_message(stats)
        else:
            LOGGER.debug('Daily digest will not be sent')

        self._write_state()

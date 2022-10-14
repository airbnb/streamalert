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
import boto3

from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


class StatsPublisher:
    """Run queries to generate statistics on alerts."""

    DEFAULT_STATS_SNS_TOPIC_SUFFIX = '{}_streamalert_rule_staging_stats'

    def __init__(self, config, athena_client, current_time):
        self._topic_arn = self.formatted_sns_topic_arn(config)
        self._athena_client = athena_client
        self._current_time = current_time

    @classmethod
    def formatted_sns_topic_arn(cls, config):
        """Format the sns topic into and aws ARN

        Args:
            config: Loaded config from conf/ containing user defined topic (if available)

        Return:
            str: Formatted SNS topic arn using either the config option or default topic
        """
        prefix = config['global']['account']['prefix']
        topic = config['lambda']['rule_promotion_config'].get(
            'digest_sns_topic', cls.DEFAULT_STATS_SNS_TOPIC_SUFFIX.format(prefix))
        return 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
            region=config['global']['account']['region'],
            account_id=config['global']['account']['aws_account_id'],
            topic=topic)

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
        return '\n\n'.join(str(stat) for stat in sorted(
            stats, reverse=True)) if stats else 'No currently staged rules to report on'

    def _query_alerts(self, stat):
        """Execute a query for all alerts for a rule so the user can be sent the results

        Args:
            rule_name (str): Name of the rule to query for alert results

        Returns:
            str: Execution ID for running Athena query
        """
        info_statement = stat.sql_info_statement
        LOGGER.debug('Querying alert info for rule \'%s\': %s', stat.rule_name, info_statement)

        response = self._athena_client.run_async_query(info_statement)

        return response['QueryExecutionId']

    def _publish_message(self, stats):
        """Publish the alert statistics message to SNS

        Args:
            stats (list<StagingStatistic>): Group of rule staging statistics
                that are being reported on
        """
        LOGGER.info('Sending daily message digest at %s', self._current_time)

        sns_client = boto3.resource('sns').Topic(self._topic_arn)

        subject = f'Alert statistics for {len(stats)} staged rule(s) [{self._current_time} UTC]'

        sns_client.publish(Message=self._format_digest(stats), Subject=subject)

    def publish(self, stats):
        """Public method for publishing alert statistics message to SNS

        Args:
            stats (list<StagingStatistic>): Group of rule staging statistics
                that are being reported on
        """
        for stat in stats:
            # If there are no alerts, do not run the comprehensive query
            if not stat:
                continue

            stat.execution_id = self._query_alerts(stat)

        self._publish_message(stats)

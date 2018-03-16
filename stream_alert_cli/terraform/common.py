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
from collections import defaultdict


DEFAULT_SNS_MONITORING_TOPIC = 'stream_alert_monitoring'


class InvalidClusterName(Exception):
    """Exception for invalid cluster names"""
    pass


def infinitedict():
    """Create arbitrary levels of dictionary key/values"""
    return defaultdict(infinitedict)


def monitoring_topic_arn(config):
    """Return the ARN of the monitoring SNS topic"""
    infrastructure_config = config['global']['infrastructure']

    topic_name = (
        DEFAULT_SNS_MONITORING_TOPIC
        if infrastructure_config['monitoring'].get('create_sns_topic')
        else infrastructure_config['monitoring']['sns_topic_name']
    )

    return 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
        region=config['global']['account']['region'],
        account_id=config['global']['account']['aws_account_id'],
        topic=topic_name
    )

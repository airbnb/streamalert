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


DEFAULT_SNS_MONITORING_TOPIC_SUFFIX = '{}_streamalert_monitoring'


class InvalidClusterName(Exception):
    """Exception for invalid cluster names"""


def infinitedict(initial_value=None):
    """Create arbitrary levels of dictionary key/values"""
    initial_value = initial_value or {}

    # Recursively cast any subdictionary entries in the initial value to infinitedicts
    for key, value in initial_value.items():
        if isinstance(value, dict):
            initial_value[key] = infinitedict(value)

    return defaultdict(infinitedict, initial_value)


def monitoring_topic_name(config):
    """Return the name of the monitoring SNS topic"""
    infra_monitoring_config = config['global']['infrastructure']['monitoring']
    prefix = config['global']['account']['prefix']
    topic_name = (
        DEFAULT_SNS_MONITORING_TOPIC_SUFFIX.format(prefix)
        if infra_monitoring_config.get('create_sns_topic')
        else infra_monitoring_config['sns_topic_name']
    )
    return topic_name


def monitoring_topic_arn(config):
    """Return the ARN of the monitoring SNS topic"""
    return 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
        region=config['global']['account']['region'],
        account_id=config['global']['account']['aws_account_id'],
        topic=monitoring_topic_name(config)
    )


class MisconfigurationError(ValueError):
    """This error is thrown when StreamAlert is misconfigured."""

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
from collections import defaultdict

DEFAULT_SNS_MONITORING_TOPIC_SUFFIX = '{}_streamalert_monitoring'
DEFAULT_S3_LOGGING_BUCKET_SUFFIX = '{}-streamalert-s3-logging'
DEFAULT_TERRAFORM_STATE_BUCKET_SUFFIX = '{}-streamalert-terraform-state'


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
    default_topic = DEFAULT_SNS_MONITORING_TOPIC_SUFFIX.format(
        config['global']['account']['prefix'])
    if 'monitoring' not in config['global']['infrastructure']:
        return default_topic, True  # Use the default name and create the sns topic

    sns_topic_name = config['global']['infrastructure']['monitoring'].get(
        'sns_topic_name', default_topic)
    return sns_topic_name, sns_topic_name == default_topic


def monitoring_topic_arn(config):
    """Return the ARN of the monitoring SNS topic"""
    return 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
        region=config['global']['account']['region'],
        account_id=config['global']['account']['aws_account_id'],
        topic=monitoring_topic_name(config)[0])


def s3_access_logging_bucket(config):
    """Get the bucket name to be used for S3 Server Access Logging

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        tuple (string, bool): The bucket name to be used for S3 Server Access Logging, and
            False if the bucket should NOT be created (eg: a pre-existing bucket name is provided)
    """
    # If a bucket name is specified for S3 event logging, we can assume the bucket
    # should NOT be created
    default_name = DEFAULT_S3_LOGGING_BUCKET_SUFFIX.format(config['global']['account']['prefix'])
    if 's3_access_logging' not in config['global']['infrastructure']:
        return default_name, True  # Use the default name and create the bucket

    bucket_name = config['global']['infrastructure']['s3_access_logging'].get(
        'bucket_name', default_name)
    return bucket_name, bucket_name == default_name


def terraform_state_bucket(config):
    """Get the bucket name to be used for the remote Terraform state

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        string: The bucket name to be used for the remote Terraform state
    """
    # If a bucket name is specified for the remote Terraform state, we can assume the bucket
    # should NOT be created
    default_name = DEFAULT_TERRAFORM_STATE_BUCKET_SUFFIX.format(
        config['global']['account']['prefix'])
    if 'terraform' not in config['global']:
        return default_name, True  # Use the default name and create the bucket

    bucket_name = config['global']['terraform'].get('bucket_name', default_name)
    return bucket_name, bucket_name == default_name


def generate_tf_outputs(cluster_dict, module_name, outputs):
    """Add the outputs to the Terraform cluster dict.

    Args:
        cluster_dict (defaultdict): The dict containing all Terraform config for
            a given cluster.
        module_name (str): The name of the terraform module for which outputs should be configured.
            This is typically formatted like: module-name_cluster-name.
        outputs (list): Names of outputs that should be included
    """
    for output_var in sorted(outputs):
        cluster_dict['output'][f'{module_name}_{output_var}'] = {
            'value': f'${{module.{module_name}.{output_var}}}',
            'sensitive': 'true'
        }

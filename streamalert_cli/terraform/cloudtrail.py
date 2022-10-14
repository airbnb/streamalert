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
from streamalert.shared.logger import get_logger
from streamalert_cli.terraform.cloudwatch_destinations import \
    generate_cloudwatch_destinations_internal
from streamalert_cli.terraform.common import s3_access_logging_bucket
from streamalert_cli.terraform.s3_events import generate_s3_events_by_bucket

LOGGER = get_logger(__name__)


def generate_cloudtrail(cluster_name, cluster_dict, config):
    """Add the CloudTrail module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the cloudtrail module
    """
    modules = config['clusters'][cluster_name]['modules']
    settings = modules['cloudtrail']
    if not settings.get('enabled', True):
        LOGGER.debug('CloudTrail module is not enabled')
        return True  # not an error

    region = config['global']['account']['region']
    prefix = config['global']['account']['prefix']
    send_to_cloudwatch = settings.get('send_to_cloudwatch', False)
    s3_settings = settings.get('s3_settings', {})
    enable_s3_events = s3_settings.get('enable_events', False)

    s3_bucket_name = s3_settings.get('bucket_name',
                                     f'{prefix}-{cluster_name}-streamalert-cloudtrail')

    primary_account_id = config['global']['account']['aws_account_id']
    account_ids = set(s3_settings.get('cross_account_ids', []))
    account_ids.add(primary_account_id)
    account_ids = sorted(account_ids)

    logging_bucket, _ = s3_access_logging_bucket(config)  # Just get the bucket name from the tuple

    module_info = {
        'source': './modules/tf_cloudtrail',
        'primary_account_id': primary_account_id,
        'region': region,
        'prefix': prefix,
        'cluster': cluster_name,
        's3_cross_account_ids': account_ids,
        's3_logging_bucket': logging_bucket,
        's3_bucket_name': s3_bucket_name,
    }

    # These have defaults in the terraform module, so only override if it's set in the config
    settings_with_defaults = {
        'enable_logging',
        'is_global_trail',
        'send_to_sns',
        'allow_cross_account_sns',
    }
    for value in settings_with_defaults:
        if value in settings:
            module_info[value] = settings[value]

    if 'event_selector_type' in s3_settings:
        module_info['s3_event_selector_type'] = s3_settings.get('event_selector_type')

    if send_to_cloudwatch:
        if not generate_cloudtrail_cloudwatch(cluster_name, cluster_dict, config, settings, prefix,
                                              region):
            return False

        module_info['cloudwatch_logs_role_arn'] = (
            '${{module.cloudtrail_cloudwatch_{}.cloudtrail_to_cloudwatch_logs_role}}'.format(
                cluster_name))
        module_info['cloudwatch_logs_group_arn'] = (
            f'${{module.cloudtrail_cloudwatch_{cluster_name}.cloudwatch_logs_group_arn}}')

    cluster_dict['module'][f'cloudtrail_{cluster_name}'] = module_info

    if enable_s3_events:
        ignore_digest = s3_settings.get('ignore_digest', True)
        s3_event_account_ids = account_ids
        # Omit the primary account ID from the event notifications to avoid duplicative processing
        if send_to_cloudwatch:
            s3_event_account_ids = [
                account_id for account_id in account_ids if account_id != primary_account_id
            ]
        bucket_info = {
            s3_bucket_name: [{
                'filter_prefix':
                f'AWSLogs/{account_id}/CloudTrail/' if ignore_digest else f'AWSLogs/{account_id}/'
            } for account_id in s3_event_account_ids]
        }

        generate_s3_events_by_bucket(
            cluster_name,
            cluster_dict,
            config,
            bucket_info,
            module_prefix='cloudtrail',
        )

    return True


def generate_cloudtrail_cloudwatch(cluster_name, cluster_dict, config, settings, prefix, region):
    """Add the CloudTrail to CloudWatch Logs Group module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        settings (dict): Settings for the cloudtrail module for this cluster

    Returns:
        bool: Result of applying the cloudtrail to cloudwatch logs module
    """
    module_info = {
        'source': './modules/tf_cloudtrail/modules/tf_cloudtrail_cloudwatch',
        'region': region,
        'prefix': prefix,
        'cluster': cluster_name,
    }

    # These have defaults in the terraform module, so only override if it's set in the config
    settings_with_defaults = {'exclude_home_region_events', 'retention_in_days'}
    for value in settings_with_defaults:
        if value in settings:
            module_info[value] = settings[value]

    destination_arn = settings.get('cloudwatch_destination_arn')
    if not destination_arn:
        fmt = '${{module.cloudwatch_logs_destination_{}_{}.cloudwatch_logs_destination_arn}}'
        destination_arn = fmt.format(cluster_name, region)
        if not generate_cloudwatch_destinations_internal(cluster_name, cluster_dict, config):
            return False

    module_info['cloudwatch_destination_arn'] = destination_arn

    cluster_dict['module'][f'cloudtrail_cloudwatch_{cluster_name}'] = module_info

    return True

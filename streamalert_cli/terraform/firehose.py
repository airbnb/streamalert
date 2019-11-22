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
from streamalert.classifier.clients import FirehoseClient
from streamalert_cli.terraform.common import monitoring_topic_arn


def generate_firehose(logging_bucket, main_dict, config):
    """Generate the Firehose Terraform modules

    Args:
        config (CLIConfig): The loaded StreamAlert Config
        main_dict (infinitedict): The Dict to marshal to a file
        logging_bucket (str): The name of the global logging bucket
    """
    if not config['global']['infrastructure'].get('firehose', {}).get('enabled'):
        return

    firehose_config = config['global']['infrastructure']['firehose']
    firehose_s3_bucket_suffix = firehose_config.get('s3_bucket_suffix', 'streamalert.data')
    firehose_s3_bucket_name = '{}.{}'.format(config['global']['account']['prefix'],
                                             firehose_s3_bucket_suffix)

    # Firehose Setup module
    main_dict['module']['kinesis_firehose_setup'] = {
        'source': './modules/tf_kinesis_firehose_setup',
        'account_id': config['global']['account']['aws_account_id'],
        'prefix': config['global']['account']['prefix'],
        'region': config['global']['account']['region'],
        's3_logging_bucket': logging_bucket,
        's3_bucket_name': firehose_s3_bucket_name,
        'kms_key_id': '${aws_kms_key.server_side_encryption.key_id}'
    }

    enabled_logs = FirehoseClient.load_enabled_log_sources(
        config['global']['infrastructure']['firehose'],
        config['logs'],
        force_load=True
    )

    log_alarms_config = config['global']['infrastructure']['firehose'].get('enabled_logs', {})

    # Add the Delivery Streams individually
    for log_stream_name, log_type_name in enabled_logs.items():
        module_dict = {
            'source': './modules/tf_kinesis_firehose_delivery_stream',
            'buffer_size': (
                config['global']['infrastructure']['firehose'].get('buffer_size', 64)
            ),
            'buffer_interval': (
                config['global']['infrastructure']['firehose'].get('buffer_interval', 300)
            ),
            'compression_format': (
                config['global']['infrastructure']['firehose'].get('compression_format', 'GZIP')
            ),
            'use_prefix': config['global']['infrastructure']['firehose'].get('use_prefix', True),
            'prefix': config['global']['account']['prefix'],
            'log_name': log_stream_name,
            'role_arn': '${module.kinesis_firehose_setup.firehose_role_arn}',
            's3_bucket_name': firehose_s3_bucket_name,
            'kms_key_arn': '${aws_kms_key.server_side_encryption.arn}'
        }

        # Try to get alarm info for this specific log type
        alarm_info = log_alarms_config.get(log_type_name)
        if not alarm_info and ':' in log_type_name:
            # Fallback on looking for alarm info for the parent log type
            alarm_info = log_alarms_config.get(log_type_name.split(':')[0])

        if alarm_info and alarm_info.get('enable_alarm'):
            module_dict['enable_alarm'] = True

            # There are defaults of these defined in the terraform module, so do
            # not set the variable values unless explicitly specified
            if alarm_info.get('log_min_count_threshold'):
                module_dict['alarm_threshold'] = alarm_info.get('log_min_count_threshold')

            if alarm_info.get('evaluation_periods'):
                module_dict['evaluation_periods'] = alarm_info.get('evaluation_periods')

            if alarm_info.get('period_seconds'):
                module_dict['period_seconds'] = alarm_info.get('period_seconds')

            if alarm_info.get('alarm_actions'):
                if not isinstance(alarm_info.get('alarm_actions'), list):
                    module_dict['alarm_actions'] = [alarm_info.get('alarm_actions')]
                else:
                    module_dict['alarm_actions'] = alarm_info.get('alarm_actions')
            else:
                module_dict['alarm_actions'] = [monitoring_topic_arn(config)]

        main_dict['module']['kinesis_firehose_{}'.format(log_stream_name)] = module_dict

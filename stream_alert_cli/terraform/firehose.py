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
from stream_alert.rule_processor.firehose import StreamAlertFirehose

def generate_firehose(config, main_dict, logging_bucket):
    """Generate the Firehose Terraform modules

    Args:
        config (CLIConfig): The loaded StreamAlert Config
        main_dict (infinitedict): The Dict to marshal to a file
        logging_bucket (str): The name of the global logging bucket
    """
    if not config['global']['infrastructure'].get('firehose', {}).get('enabled'):
        return

    sa_firehose = StreamAlertFirehose(config['global']['account']['region'],
                                      config['global']['infrastructure']['firehose'],
                                      config['logs'])

    firehose_config = config['global']['infrastructure']['firehose']
    firehose_s3_bucket_suffix = firehose_config.get('s3_bucket_suffix', 'streamalert.data')
    firehose_s3_bucket_name = '{}.{}'.format(config['global']['account']['prefix'],
                                             firehose_s3_bucket_suffix)

    # Firehose Setup module
    main_dict['module']['kinesis_firehose_setup'] = {
        'source': 'modules/tf_stream_alert_kinesis_firehose_setup',
        'account_id': config['global']['account']['aws_account_id'],
        'prefix': config['global']['account']['prefix'],
        'region': config['global']['account']['region'],
        's3_logging_bucket': logging_bucket,
        's3_bucket_name': firehose_s3_bucket_name
    }

    # Add the Delivery Streams individually
    for enabled_log in sa_firehose.enabled_logs:
        main_dict['module']['kinesis_firehose_{}'.format(enabled_log)] = {
            'source': 'modules/tf_stream_alert_kinesis_firehose_delivery_stream',
            'buffer_size': config['global']['infrastructure']
                           ['firehose'].get('buffer_size', 64),
            'buffer_interval': config['global']['infrastructure']
                               ['firehose'].get('buffer_interval', 300),\
            'compression_format': config['global']['infrastructure']
                                  ['firehose'].get('compression_format', 'GZIP'),
            'log_name': enabled_log,
            'role_arn': '${module.kinesis_firehose_setup.firehose_role_arn}',
            's3_bucket_name': firehose_s3_bucket_name
        }

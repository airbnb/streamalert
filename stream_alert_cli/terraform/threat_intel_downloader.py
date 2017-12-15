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
from stream_alert_cli.terraform._common import DEFAULT_SNS_MONITORING_TOPIC, infinitedict

def generate_threat_intel_downloader(config):
    """Generate Threat Intel Downloader Terrafrom

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        dict: Athena dict to be marshalled to JSON
    """
    # Use the monitoring topic as a dead letter queue
    infrastructure_config = config['global'].get('infrastructure')
    dlq_topic = (DEFAULT_SNS_MONITORING_TOPIC
                 if infrastructure_config.get('monitoring', {}).get('create_sns_topic')
                 else infrastructure_config.get('monitoring', {}).get('sns_topic_name',
                                                                      DEFAULT_SNS_MONITORING_TOPIC))

    # Threat Intel Downloader module
    ti_downloader_config = config['lambda']['threat_intel_downloader_config']
    ti_downloader_dict = infinitedict()
    ti_downloader_dict['module']['threat_intel_downloader'] = {
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'source': 'modules/tf_threat_intel_downloader',
        'lambda_function_arn': '${module.threat_intel_downloader.lambda_arn}',
        'lambda_handler': ti_downloader_config['handler'],
        'lambda_memory': ti_downloader_config.get('memory', '128'),
        'lambda_timeout': ti_downloader_config.get('timeout', '60'),
        'lambda_s3_bucket': ti_downloader_config['source_bucket'],
        'lambda_s3_key': ti_downloader_config['source_object_key'],
        'lambda_log_level': ti_downloader_config.get('log_level', 'info'),
        'interval': ti_downloader_config.get('interval', 'rate(1 day)'),
        'current_version': ti_downloader_config['current_version'],
        'prefix': config['global']['account']['prefix'],
        'monitoring_sns_topic': dlq_topic,
        'table_rcu': ti_downloader_config.get('table_rcu', '10'),
        'table_wcu': ti_downloader_config.get('table_wcu', '10'),
        'ioc_keys': ti_downloader_config.get('ioc_keys',
                                             ['expiration_ts', 'itype', 'source', 'type', 'value']),
        'ioc_filters': ti_downloader_config.get('ioc_filters', ['crowdstrike', '@airbnb.com']),
        'ioc_types': ti_downloader_config.get('ioc_types', ['domain', 'ip', 'md5']),
        'autoscale': ti_downloader_config.get('autoscale', False),
        'max_read_capacity': ti_downloader_config.get('max_read_capacity', '5'),
        'min_read_capacity': ti_downloader_config.get('min_read_capacity', '5'),
        'target_utilization': ti_downloader_config.get('target_utilization', '70')
    }
    return ti_downloader_dict

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
from streamalert.shared import THREAT_INTEL_DOWNLOADER_NAME
from streamalert_cli.terraform.common import (infinitedict,
                                              monitoring_topic_name)
from streamalert_cli.terraform.lambda_module import generate_lambda


def generate_threat_intel_downloader(config):
    """Generate Threat Intel Downloader Terrafrom

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        dict: Athena dict to be marshalled to JSON
    """
    # Use the monitoring topic as a dead letter queue
    dlq_topic, _ = monitoring_topic_name(config)

    prefix = config['global']['account']['prefix']

    # Threat Intel Downloader module
    tid_config = config['lambda']['threat_intel_downloader_config']

    # old format of config used interval, but tf_lambda expects 'schedule_expression'
    if 'schedule_expression' not in tid_config:
        tid_config['schedule_expression'] = tid_config.get('interval', 'rate(1 day)')

    result = infinitedict()

    # Set variables for the threat intel downloader configuration
    result['module']['threat_intel_downloader_iam'] = {
        'source': './modules/tf_threat_intel_downloader',
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'prefix': prefix,
        'function_role_id': '${module.threat_intel_downloader.role_id}',
        'function_alias_arn': '${module.threat_intel_downloader.function_alias_arn}',
        'function_cloudwatch_log_group_name': '${module.threat_intel_downloader.log_group_name}',
        'monitoring_sns_topic': dlq_topic,
        'table_rcu': tid_config.get('table_rcu', '10'),
        'table_wcu': tid_config.get('table_wcu', '10'),
        'max_read_capacity': tid_config.get('max_read_capacity', '5'),
        'min_read_capacity': tid_config.get('min_read_capacity', '5'),
        'target_utilization': tid_config.get('target_utilization', '70')
    }

    result['module']['threat_intel_downloader'] = generate_lambda(
        f'{prefix}_streamalert_{THREAT_INTEL_DOWNLOADER_NAME}',
        'streamalert.threat_intel_downloader.main.handler', tid_config, config)

    return result

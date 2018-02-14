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
from stream_alert.shared import metrics
from stream_alert_cli.terraform._common import DEFAULT_SNS_MONITORING_TOPIC, infinitedict


def generate_athena(config):
    """Generate Athena Terraform.

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        dict: Athena dict to be marshalled to JSON
    """
    athena_dict = infinitedict()
    athena_config = config['lambda']['athena_partition_refresh_config']

    data_buckets = set()
    for refresh_type in athena_config['refresh_type']:
        data_buckets.update(set(athena_config['refresh_type'][refresh_type]))

    prefix = config['global']['account']['prefix']
    database = athena_config.get('database_name', '').strip()
    if database == '':
        database = 'streamalert'

    results_bucket_name = athena_config.get('results_bucket', '').strip()
    if results_bucket_name == '':
        results_bucket_name = '{}.streamalert.athena-results'.format(prefix)

    queue_name = athena_config.get('queue_name', '').strip()
    if queue_name == '':
        queue_name = '{}_streamalert_athena_data_bucket_notifications'.format(prefix)

    athena_dict['module']['stream_alert_athena'] = {
        's3_logging_bucket': '{}.streamalert.s3-logging'.format(prefix),
        'source': 'modules/tf_stream_alert_athena',
        'database_name': database,
        'queue_name': queue_name,
        'results_bucket': results_bucket_name,
        'lambda_handler': athena_config['handler'],
        'lambda_memory': athena_config.get('memory', '128'),
        'lambda_timeout': athena_config.get('timeout', '60'),
        'lambda_s3_bucket': athena_config['source_bucket'],
        'lambda_s3_key': athena_config['source_object_key'],
        'lambda_log_level': athena_config.get('log_level', 'info'),
        'athena_data_buckets': list(data_buckets),
        'refresh_interval': athena_config.get('refresh_interval', 'rate(10 minutes)'),
        'current_version': athena_config['current_version'],
        'enable_metrics': athena_config.get('enable_metrics', False),
        'prefix': prefix
    }

    # Cloudwatch monitoring setup
    monitoring_config = config['global'].get('infrastructure', {}).get('monitoring', {})
    sns_topic_name = DEFAULT_SNS_MONITORING_TOPIC if monitoring_config.get(
        'create_sns_topic') else monitoring_config.get('sns_topic_name')
    athena_dict['module']['athena_monitoring'] = {
        'source': 'modules/tf_stream_alert_monitoring',
        'sns_topic_arn': 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
            region=config['global']['account']['region'],
            account_id=config['global']['account']['aws_account_id'],
            topic=sns_topic_name
        ),
        'lambda_functions': ['{}_streamalert_athena_partition_refresh'.format(prefix)],
        'kinesis_alarms_enabled': False
    }

    # Metrics setup
    if not athena_config.get('enable_metrics', False):
        return athena_dict

    # Check to see if there are any metrics configured for the athena function
    current_metrics = metrics.MetricLogger.get_available_metrics()
    if metrics.ATHENA_PARTITION_REFRESH_NAME not in current_metrics:
        return athena_dict

    metric_prefix = 'AthenaRefresh'
    filter_pattern_idx, filter_value_idx = 0, 1

    # Add filters for the cluster and aggregate
    # Use a list of strings that represnt the following comma separated values:
    #   <filter_name>,<filter_pattern>,<value>
    filters = ['{},{},{}'.format('{}-{}'.format(metric_prefix, metric),
                                 settings[filter_pattern_idx],
                                 settings[filter_value_idx])
               for metric, settings in
               current_metrics[metrics.ATHENA_PARTITION_REFRESH_NAME].iteritems()]

    athena_dict['module']['stream_alert_athena']['athena_metric_filters'] = filters

    return athena_dict

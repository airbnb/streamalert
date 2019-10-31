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
from streamalert.shared import metrics
from streamalert_cli.manage_lambda.package import AthenaPackage
from streamalert_cli.terraform.common import infinitedict, monitoring_topic_name


def generate_athena(config):
    """Generate Athena Terraform.

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        dict: Athena dict to be marshalled to JSON
    """
    athena_dict = infinitedict()
    athena_config = config['lambda']['athena_partition_refresh_config']

    data_buckets = sorted(athena_config['buckets'])

    prefix = config['global']['account']['prefix']
    database = athena_config.get('database_name', '{}_streamalert'.format(prefix))

    results_bucket_name = athena_config.get(
        'results_bucket',
        '{}.streamalert.athena-results'.format(prefix)
    ).strip()

    queue_name = athena_config.get(
        'queue_name',
        '{}_streamalert_athena_s3_notifications'.format(prefix)
    ).strip()

    athena_dict['module']['stream_alert_athena'] = {
        's3_logging_bucket': config['global']['s3_access_logging']['logging_bucket'],
        'source': './modules/tf_athena',
        'database_name': database,
        'queue_name': queue_name,
        'results_bucket': results_bucket_name,
        'kms_key_id': '${aws_kms_key.server_side_encryption.key_id}',
        'lambda_handler': AthenaPackage.lambda_handler,
        'lambda_memory': athena_config.get('memory', '128'),
        'lambda_timeout': athena_config.get('timeout', '60'),
        'lambda_log_level': athena_config.get('log_level', 'info'),
        'athena_data_buckets': data_buckets,
        'concurrency_limit': athena_config.get('concurrency_limit', 10),
        'account_id': config['global']['account']['aws_account_id'],
        'prefix': prefix
    }

    # Cloudwatch monitoring setup
    sns_topic_name = monitoring_topic_name(config)
    athena_dict['module']['athena_monitoring'] = {
        'source': './modules/tf_monitoring',
        'sns_topic_arn': 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
            region=config['global']['account']['region'],
            account_id=config['global']['account']['aws_account_id'],
            topic=sns_topic_name
        ),
        'lambda_functions': ['{}_streamalert_athena_partition_refresh'.format(prefix)],
        'kinesis_alarms_enabled': False
    }

    # Metrics setup
    if not athena_config.get('enable_custom_metrics', False):
        return athena_dict

    # Check to see if there are any metrics configured for the athena function
    current_metrics = metrics.MetricLogger.get_available_metrics()
    if metrics.ATHENA_PARTITION_REFRESH_NAME not in current_metrics:
        return athena_dict

    metric_prefix = 'AthenaRefresh'
    filter_pattern_idx, filter_value_idx = 0, 1

    # Add filters for the cluster and aggregate
    # Use a list of strings that represent the following comma separated values:
    #   <filter_name>,<filter_pattern>,<value>
    filters = ['{},{},{}'.format('{}-{}'.format(metric_prefix, metric),
                                 settings[filter_pattern_idx],
                                 settings[filter_value_idx])
               for metric, settings in
               current_metrics[metrics.ATHENA_PARTITION_REFRESH_NAME].items()]

    athena_dict['module']['stream_alert_athena']['athena_metric_filters'] = filters

    return athena_dict

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
from stream_alert_cli.terraform._common import infinitedict

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

    athena_dict['module']['stream_alert_athena'] = {
        'source': 'modules/tf_stream_alert_athena',
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
        'prefix': config['global']['account']['prefix']
    }

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

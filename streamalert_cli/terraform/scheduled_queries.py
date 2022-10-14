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
from streamalert.shared.config import (athena_partition_buckets_tf,
                                       athena_query_results_bucket)
from streamalert_cli.terraform.common import monitoring_topic_arn


def generate_scheduled_queries_module_configuration(config):
    streamquery_config = config.get('scheduled_queries', {})
    prefix = config['global']['account']['prefix']

    # FIXME (derek.wang)
    # should violently break if athena configurations don't exist.
    # Alternatively, could read off streamalert_athena module and get more outputs from that.
    athena_config = config['lambda']['athena_partitioner_config']

    # FIXME (derek.wang) make consistent with streamalert_athena module,
    # maybe make this dependent on output of that module?
    database = athena_config.get('database_name', f'{prefix}_streamalert')

    # The results bucket cannot reference the output from the streamalert_athena module:
    #   '${module.athena_partitioner_iam.results_bucket_arn}'
    # Because it takes a bucket name, not an ARN
    # FIXME (derek.wang) DRY out this code
    results_bucket = athena_query_results_bucket(config)

    athena_s3_buckets = athena_partition_buckets_tf(config)

    # Copy the config over directly
    scheduled_queries_module = streamquery_config.get('config', {})

    # Derive a bunch of required fields from other
    scheduled_queries_module.update({
        'source': './modules/tf_scheduled_queries',
        'prefix': prefix,
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'athena_database': database,
        'athena_results_bucket': results_bucket,
        'athena_s3_buckets': athena_s3_buckets,
        'lambda_handler': 'streamalert.scheduled_queries.main.handler',
    })

    # Transforms the query_packs key
    scheduled_queries_module['query_packs'] = [{
        'name': key,
        'schedule_expression': item['schedule_expression'],
        'description': item['description']
    } for key, item in streamquery_config.get('packs', {}).items()]

    # Take lambda_config and move stuff into here, prefixed with "lambda_*"
    lambda_config = streamquery_config.get('lambda_config', {})
    lambda_fields = [
        'log_level', 'log_retention_days', 'memory', 'timeout', 'alarms_enabled', 'error_threshold',
        'error_period_secs', 'error_evaluation_periods'
    ]
    for field in lambda_fields:
        if field in lambda_config:
            scheduled_queries_module[f'lambda_{field}'] = lambda_config[field]

    if scheduled_queries_module.get('lambda_alarms_enabled', False):
        scheduled_queries_module['lambda_alarm_actions'] = [monitoring_topic_arn(config)]

    return {'module': {'scheduled_queries': scheduled_queries_module}}

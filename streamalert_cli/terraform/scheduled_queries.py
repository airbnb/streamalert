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
from streamalert_cli.manage_lambda.package import ScheduledQueriesPackage


def generate_scheduled_queries_module_configuration(config):
    streamquery_config = config.get('scheduled_queries', {})
    prefix = config['global']['account']['prefix']

    # FIXME (derek.wang)
    # should violently break if athena configurations don't exist.
    # Alternatively, could read off streamalert_athena module and get more outputs from that.
    athena_config = config['lambda']['athena_partition_refresh_config']

    # FIXME (derek.wang) make consistent with streamalert_athena module,
    # maybe make this dependent on output of that module?
    database = athena_config.get('database_name', '{}_streamalert'.format(prefix))

    # The results bucket cannot reference the output from the streamalert_athena module:
    #   '${module.streamalert_athena.results_bucket_arn}'
    # Because it takes a bucket name, not an ARN
    # FIXME (derek.wang) DRY out this code
    results_bucket = athena_config.get(
        'results_bucket',
        '{}.streamalert.athena-results'.format(prefix)
    ).strip()

    generated_config = {'module': {}}
    generated_config['module']['scheduled_queries'] = {
        'source': './modules/tf_scheduled_queries',

        'prefix': prefix,
        'destination_kinesis_stream': streamquery_config['config']['destination_kinesis'],
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'athena_database': database,
        'athena_results_bucket': results_bucket,
        'athena_s3_buckets': sorted(athena_config.get('buckets', [])),
        'sfn_timeout_secs': streamquery_config['config'].get('sfn_timeout_secs', None),
        'sfn_wait_secs': streamquery_config['config'].get('sfn_wait_secs', None),

        'query_packs': [
            {
                'name': key,
                'schedule_expression': item['schedule_expression'],
                'description': item['description']
            }
            for key, item
            in streamquery_config.get('packs', {}).items()
        ],

        'lambda_filename': ScheduledQueriesPackage.package_name + '.zip',
        'lambda_handler': ScheduledQueriesPackage.lambda_handler,
    }

    return generated_config

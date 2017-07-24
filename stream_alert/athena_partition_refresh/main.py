'''
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
'''

import json
import logging
import os

from datetime import datetime

import backoff
import boto3

logging.basicConfig()
LEVEL = os.environ.get('LOGGER_LEVEL', 'INFO')
LOGGER = logging.getLogger('StreamAlertAthena')
LOGGER.setLevel(LEVEL.upper())

ATHENA_CLIENT = None
DATABASE_DEFAULT = 'default'


def _load_config():
    """Load the Athena Lambda configuration file

    Returns:
        [dict] Configuration settings by file, includes two keys:
            lambda: All lambda function settings
            global: StreamAlert global settings
    """
    config_files = ('lambda', 'global')
    config = {}
    for config_file in config_files:
        with open('conf/{}.json'.format(config_file)) as config_fh:
            try:
                config[config_file] = json.load(config_fh)
            except ValueError:
                LOGGER.error('The \'%s\' file could not be loaded into json', config_file)
                return

    return config


def _backoff_handler(details):
    """Simple logging handler for when polling backoff occurs."""
    LOGGER.debug('Trying again in %f seconds after %d tries calling %s',
                 details['wait'],
                 details['tries'],
                 details['target'])


def _success_handler(details):
    """Simple logging handler for when polling backoff occurs."""
    LOGGER.debug('Completed after %d tries calling %s',
                 details['tries'],
                 details['target'])


def check_query_status(query_execution_id):
    """Check in on the running query, back off if the job is running or queued

    Returns:
        [string]: The result of the query, this can be SUCCEEDED, FAILED, or CANCELLED.
                  Reference http://bit.ly/2uuRtda
    """
    @backoff.on_predicate(backoff.fibo,
                          lambda status: status in ('QUEUED', 'RUNNING'),
                          max_value=10,
                          jitter=backoff.full_jitter,
                          on_backoff=_backoff_handler,
                          on_success=_success_handler)
    def _get_query_execution(query_execution_id):
        return ATHENA_CLIENT.get_query_execution(
            QueryExecutionId=query_execution_id
        )['QueryExecution']['Status']['State']

    return _get_query_execution(query_execution_id)


def run_athena_query(**kwargs):
    """Helper function to run Athena queries

    Keyword Args:
        query [string]: The SQL query to execute
        database [string]: The database to execute the query against
        results_bucket [string]: The S3 bucket to store query results
        results_path [string]: The S3 key to store results

    Returns (one or the other):
        [bool]: Query success
        [dict]: Query result response
    """
    LOGGER.debug('Executing query: %s', kwargs['query'])
    query_execution_resp = ATHENA_CLIENT.start_query_execution(
        QueryString=kwargs['query'],
        QueryExecutionContext={'Database': kwargs.get('database', DATABASE_DEFAULT)},
        ResultConfiguration={'OutputLocation': '{}/{}'.format(
            kwargs['results_bucket'],
            kwargs['results_path']
        )}
    )
    query_execution_result = check_query_status(query_execution_resp['QueryExecutionId'])
    if query_execution_result != 'SUCCEEDED':
        LOGGER.error(
            'The query %s returned %s, exiting!',
            kwargs['query'],
            query_execution_result)
        return False

    query_results_resp = ATHENA_CLIENT.get_query_results(
        QueryExecutionId=query_execution_resp['QueryExecutionId'],
    )

    # The idea here is to leave the processing logic to the calling functions.
    # No data being returned isn't always an indication that something is wrong.
    if not query_results_resp['ResultSet']['Rows']:
        LOGGER.debug('The query %s returned no data', kwargs['query'])

    return query_results_resp


def check_database_exists(results_bucket, results_path):
    """Verify the StreamAlert Athena database exists."""
    query_resp = run_athena_query(
        query='SHOW DATABASES LIKE \'streamalert\';',
        results_bucket=results_bucket,
        results_path=results_path
    )
    if isinstance(query_resp, dict) and not query_resp['ResultSet']['Rows']:
        LOGGER.info('The \'streamalert\' database does not exist, please create it.')
        return False

    return True


def check_table_exists(results_bucket, results_path, table_name):
    """Verify a given StreamAlert Athena table exists."""
    query_resp = run_athena_query(
        query='SHOW TABLES LIKE \'{}\';'.format(table_name),
        database='streamalert',
        results_bucket=results_bucket,
        results_path=results_path
    )
    if isinstance(query_resp, dict) and not query_resp['ResultSet']['Rows']:
        LOGGER.info('The streamalert table \'%s\' does not exist, please create it.', table_name)
        return False

    return True


def normal_partition_refresh(config, athena_results_bucket, athena_results_path):
    normal_partition_config = config['lambda']['athena_partition_refresh_config']['partitioning']['normal']
    for _, athena_table in normal_partition_config.iteritems():
        resp = run_athena_query(
            query='MSCK REPAIR TABLE {};'.format(athena_table),
            database='streamalert',
            results_bucket=athena_results_bucket,
            results_path=athena_results_path
        )
        if resp:
            LOGGER.info('Query results:')
            for row in resp['ResultSet']['Rows']:
                LOGGER.info(row)


def firehose_partition_refresh(_):
    LOGGER.error('Firehose partition refresh is not yet supported, exiting!')
    raise NotImplementedError


def handler(event, context):
    """Athena Partition Refresher Handler Function"""
    config = _load_config()
    if not config:
        LOGGER.error('No config found, exiting!')
        return

    global ATHENA_CLIENT
    ATHENA_CLIENT = boto3.client('athena', region_name=config['global']['account']['region'])

    # Athena queries need an S3 bucket for results
    athena_results_bucket = 's3://aws-athena-query-results-{}-{}'.format(
        config['global']['account']['aws_account_id'],
        config['global']['account']['region']
    )
    # Produces athena_partition_refresh/2017/01/01 keys
    athena_results_path = 'athena_partition_refresh/{}'.format(
        datetime.now().strftime('%Y/%m/%d'))

    # The StreamAlert database needs to exist before we run queries.
    if not check_database_exists(athena_results_bucket, athena_results_path):
        return

    normal_partition_refresh(config, athena_results_bucket, athena_results_path)

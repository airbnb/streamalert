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
import json
import os

import boto3
from botocore.exceptions import ClientError

from stream_alert.threat_intel_downloader.threat_stream import ThreatStream
from stream_alert.threat_intel_downloader import LOGGER, END_TIME_BUFFER
from stream_alert.threat_intel_downloader.exceptions import (
    ThreatStreamLambdaInvokeError,
    ThreatStreamConfigError
)

CONFIG_FILE_PATH = 'conf/lambda.json'


def handler(event, context):
    """Lambda handler"""
    config = load_config()
    config.update(parse_lambda_func_arn(context))
    threat_stream = ThreatStream(config)
    intelligence, next_url, continue_invoke = threat_stream.runner(event)

    if intelligence:
        LOGGER.info('Write %d IOCs to DynamoDB table', len(intelligence))
        threat_stream.write_to_dynamodb_table(intelligence)

    if context.get_remaining_time_in_millis() > END_TIME_BUFFER * 1000 and continue_invoke:
        invoke_lambda_function(next_url, config)

    LOGGER.debug("Time remaining (MS): %s", context.get_remaining_time_in_millis())

def invoke_lambda_function(next_url, config):
    """Invoke lambda function itself with next token to continually retrieve IOCs"""
    LOGGER.debug('This invoacation is invoked by lambda function self.')
    try:
        lambda_client = boto3.client('lambda', region_name=config['region'])
        lambda_client.invoke(
            FunctionName=config['function_name'],
            InvocationType='Event',
            Payload=json.dumps({'next_url': next_url}),
            Qualifier=config['qualifier']
        )
    except ClientError as err:
        LOGGER.error('Lambda client error: %s when lambda function invoke self', err)
        raise ThreatStreamLambdaInvokeError

def parse_lambda_func_arn(context):
    """Parse Lambda function arn to get function name, account id, region"""
    func_arn = context.invoked_function_arn.split(':')

    return {
        'region': func_arn[3],
        'account_id': func_arn[4],
        'function_name': func_arn[6],
        'qualifier': func_arn[7]
    }

def load_config():
    """Load the Threat Intel Downloader configuration from conf/lambda.json file

    Returns:
        (dict): Configuration for Threat Intel Downloader

    Raises:
        ThreatStreamConfigError: For invalid or missing configuration files.
    """
    config = {}
    if not os.path.exists(CONFIG_FILE_PATH):
        raise ThreatStreamConfigError('The \'{}\' config file was not found'.format(
            CONFIG_FILE_PATH))

    with open(CONFIG_FILE_PATH) as config_fh:
        try:
            config = json.load(config_fh)
        except ValueError:
            raise ThreatStreamConfigError('The \'{}\' config file is not valid JSON'.format(
                CONFIG_FILE_PATH))

    return config.get('threat_intel_downloader_config', None)

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

import boto3
from botocore.exceptions import ClientError

from stream_alert.threat_intel_downloader.threat_stream import ThreatStream
from stream_alert.threat_intel_downloader import LOGGER, END_TIME_BUFFER
from stream_alert.threat_intel_downloader.exceptions import ThreatStreamLambdaInvokeError


def handler(event, context):
    """Lambda handler"""
    LOGGER.debug('event: %s', event)
    LOGGER.debug('context: %s', context)
    LOGGER.debug('Mem. limits(MB): %d', context.memory_limit_in_mb)

    config = parse_config(context)
    threat_stream = ThreatStream(set(['domain', 'ip', 'md5']), config['region'])
    intelligence, next_url, continue_invoke = threat_stream.runner(event)

    if intelligence:
        LOGGER.debug('Write %d IOCs to DynamoDB table', len(intelligence))
        threat_stream.write_to_dynamodb_table(intelligence)

    if context.get_remaining_time_in_millis() > END_TIME_BUFFER * 1000 and continue_invoke:
        LOGGER.debug('Going to invoke lambda by itself.')
        invoke_lambda_function(next_url, context)

    LOGGER.debug("Time remaining (MS): %d", context.get_remaining_time_in_millis())

def invoke_lambda_function(next_url, config):
    try:
        lambda_client = boto3.client('lambda', region_name=config['region'])
        lambda_client.invoke(
            FunctionName=config['function_name'],
            InvocationType='Event',
            Payload=json.dumps({'next_url': next_url})
        )
    except ClientError as err:
        LOGGER.debug('Lambda client error: %s', err)
        raise ThreatStreamLambdaInvokeError

def parse_config(context):
    """Parse Lambda function arn to get function name, account id, region"""
    func_arn = context.invoked_function_arn.split(':')

    return {
        'region': func_arn[3],
        'account_id': func_arn[4],
        'function_name': func_arn[6]
    }

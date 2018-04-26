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
from __future__ import absolute_import  # Suppresses RuntimeWarning import error in Lambda
import json

import boto3
from botocore.exceptions import ClientError

from stream_alert.shared.config import load_config, parse_lambda_arn
from stream_alert.threat_intel_downloader.threat_stream import ThreatStream
from stream_alert.threat_intel_downloader import LOGGER, END_TIME_BUFFER
from stream_alert.threat_intel_downloader.exceptions import ThreatStreamLambdaInvokeError


def handler(event, context):
    """Lambda handler"""
    lambda_config = load_config(include={'lambda.json'})['lambda']
    config = lambda_config.get('threat_intel_downloader_config')
    config.update(parse_lambda_arn(context.invoked_function_arn))
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

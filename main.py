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

import logging
import os

from stream_alert.config import load_config, load_env
from stream_alert.classifier import StreamPayload, StreamPayloadHelpers
from stream_alert.rules_engine import StreamRules
from stream_alert.sink import StreamSink

from rules import (
    csirt,
    itx_corp,
    prod,
    carbonblack,
    matchers
)

logging.basicConfig()
logger = logging.getLogger('StreamAlert')
logger.setLevel(logging.INFO)

def handler(event, context):
    """StreamAlert Lambda function handler.

    Loads the configuration for the StreamAlert function which contains:
    available data sources, log formats, parser modes, and sinks.  Classifies
    logs sent into the stream into a parsed type.  Matches records against
    rules.

    Args:
        event: An AWS event mapped to a specific source/entity (kinesis stream or
            an s3 bucket event) containing data emitted to the stream.
        context: An AWS context object which provides metadata on the currently
            executing lambda function.

    Returns:
        None
    """
    logger.debug('Number of Records: %d', len(event.get('Records')))

    config = load_config()
    env = load_env(context)
    alerts_to_send = []

    for record in event.get('Records'):
        payload = StreamPayload(raw_record=record, config=config, env=env)
        payload.map_source()

        if payload.service == 's3':
            s3_file_lines = StreamPayloadHelpers.parse_s3_object(payload.raw_record)
            for line in s3_file_lines:
                data = line.rstrip()
                payload.refresh_record(data)
                payload.classify_record(data)
                process_alerts(payload, alerts_to_send)

        elif payload.service == 'kinesis':
            data = StreamPayloadHelpers.pre_parse_kinesis(payload.raw_record)
            payload.classify_record(data)
            process_alerts(payload, alerts_to_send)

    if alerts_to_send:
        if env['lambda_alias'] == 'development':
            logger.info('%s alerts triggered', len(alerts_to_send))
            for alert in alerts_to_send:
                logger.info(alert)
        StreamSink(alerts_to_send, config, env).sink()
    else:
        logger.debug('Valid data, no alerts: %s', payload)

def process_alerts(payload, alerts_to_send):
    if payload.valid:
        alerts = StreamRules.process(payload)
        if alerts:
            alerts_to_send.extend(alerts)
    else:
        logger.debug('Invalid data: %s', payload)

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
import sys

import boto3
from botocore.exceptions import ClientError

logging.basicConfig()
LOGGER = logging.getLogger('StreamAlert')

def _json_dump(alert, indent_value=None):
    def json_dict_serializer(obj):
        """Helper method for marshalling dictionary objects to JSON"""
        return obj.__dict__

    try:
        return json.dumps(alert, indent=indent_value, default=json_dict_serializer)
    except AttributeError as err:
        LOGGER.error('An error occurred while dumping object to JSON: %s', err)
        return ""


class StreamSink(object):
    """StreamSink class is used for sending actual alerts to the alert processor"""
    def __init__(self, env):
        """StreamSink initializer

        Args:
            env [dict]: loaded dictionary containing environment information
        """
        self.env = env
        self.client_lambda = boto3.client('lambda',
                                          region_name=self.env['lambda_region'])
        self.function = self.env['lambda_function_name'].replace(
            '_streamalert_rule_processor', '_streamalert_alert_processor')

    def sink(self, alerts):
        """Sink triggered alerts from the StreamRules engine.

        Args:
            alerts [list]: a list of dictionaries representating json alerts

        Sends a message to the alert processor with the following JSON format:
            {
                "record": record,
                "metadata": {
                    "rule_name": rule.rule_name,
                    "rule_description": rule.rule_function.__doc__,
                    "log": str(payload.log_source),
                    "outputs": rule.outputs,
                    "type": payload.type,
                    "source": {
                        "service": payload.service,
                        "entity": payload.entity
                    }
                }
            }
        """
        for alert in alerts:
            data = _json_dump(alert)

            try:
                response = self.client_lambda.invoke(
                    FunctionName=self.function,
                    InvocationType='Event',
                    Payload=data
                )

            except ClientError as err:
                LOGGER.exception('An error occurred while sending alert to '
                                 '\'%s\'. Error is: %s. Alert: %s',
                                 self.function,
                                 err.response,
                                 data)
                return

            if response['ResponseMetadata']['HTTPStatusCode'] != 202:
                LOGGER.error('Failed to send alert to \'%s\': %s',
                             self.function, data)
                return

            if self.env['lambda_alias'] != 'development':
                LOGGER.info('Sent alert to \'%s\' with Lambda request ID \'%s\'',
                            self.function,
                            response['ResponseMetadata']['RequestId'])

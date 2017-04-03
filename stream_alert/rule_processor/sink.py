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
import botocore

_SNS_MAX_SIZE = (256*1024)

logging.basicConfig()
logger = logging.getLogger('StreamAlert')

def json_dump(sns_dict, indent_value=None):
    def json_dict_serializer(obj):
        """Helper method for marshalling dictionary objects to JSON"""
        return obj.__dict__

    try:
        return json.dumps(sns_dict, indent=indent_value, default=json_dict_serializer)
    except AttributeError as err:
        logging.error('An error occured while dumping object to JSON: %s', err)
        return ""

class SNSMessageSizeError(Exception):
    pass

class StreamSink(object):
    def __init__(self, alerts, env):
        self.alerts = alerts
        self.env = env

    def sink(self):
        """Sink triggered alerts from the StreamRules engine.

        Group alerts to be sent to each sink, verifies that the
        sink exists in our configuration, and then sinks each
        group of alerts to the given SNS topic.

        Sends a message to SNS with the following JSON format:
            {default: [
                {
                    'rule_name': rule.rule_name,
                    'record': record,
                    'metadata': {
                        'log': str(payload.log_source),
                        'outputs': rule.outputs,
                        'type': payload.type,
                        'source': {
                            'service': payload.service,
                            'entity': payload.entity
                        }
                    }
                }
            ]}
        """
        lambda_alias = self.env['lambda_alias']

        for alert in self.alerts:
            sns_dict = {'default': [alert]}
            if lambda_alias == 'production':
                topic_arn = self._get_sns_topic_arn()
                client = boto3.client('sns', region_name=self.env['lambda_region'])
                self.publish_message(client, json_dump(sns_dict), topic_arn)
            elif lambda_alias == 'staging':
                logger.info(json_dump(sns_dict, 2))

    def _get_sns_topic_arn(self):
        """Return a properly formatted SNS ARN.

        Args:
            region: Which AWS region the SNS topic exists in.
            topic: The name of the SNS topic.
        """
        topic = self.env['lambda_function_name'].replace('_streamalert_rule_processor',
                                                         '_streamalerts')

        return 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
            region=self.env['lambda_region'],
            account_id=self.env['account_id'],
            topic=topic
        )

    @staticmethod
    def _sns_message_size_check(message):
        """Verify the SNS message is less than or equal to 256KB (SNS Limit)
        Args:
            message: A JSON string containing an alert to send to SNS.

        Returns:
            Boolean result of if the message is within the size constraint
        """
        message_size = sys.getsizeof(message)
        return 0 < message_size <= _SNS_MAX_SIZE

    def publish_message(self, client, message, topic):
        """Emit a message to SNS.

        Args:
            client: The boto3 client object.
            message: A JSON string containing a serialized alert.
            topic: The SNS topic ARN to send to.
        """
        if self._sns_message_size_check(message):
            try:
                response = client.publish(
                    TopicArn=topic,
                    Message=message,
                    Subject='StreamAlert Rules Triggered'
                )
            except botocore.exceptions.ClientError as err:
                logging.error('An error occured while publishing Alert: %s', err.response)
                raise err
            logger.info('Published %i alert(s) to %s', len(self.alerts), topic)
            logger.info('SNS MessageID: %s', response['MessageId'])
        else:
            logging.error('Cannot publish Alerts, message size is too big!')
            raise SNSMessageSizeError('SNS message size is too big! (Max: 256KB)')

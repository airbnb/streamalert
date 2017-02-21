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

import base64
import collections
import json
import logging
import sys

import boto3
import botocore

logging.basicConfig()
logger = logging.getLogger('StreamAlert')

class SNSMessageSizeError(Exception):
    pass

class StreamSink(object):
    def __init__(self, alerts, config, env):
        self.alerts = alerts
        self.env = env
        self.variables = config['variables']

    def sink(self):
        """Sink triggered alerts from the StreamRules engine.

        Group alerts to be sent to each sink, verifies that the
        sink exists in our configuration, and then sinks each
        group of alerts to the given SNS topic.

        Sends a message to SNS with the following JSON format:
            default: 'default',
            alerts: [
                'rule_name': 'name',
                'outputs': ['output1', 'output2'],
                'payload': 'message_payload'
            ]
        """
        def jdefault(obj):
            """Helper method for marshalling custom objects to JSON"""
            return obj.__dict__

        snsDict = {'default': 'default', 'alerts': self.alerts}
        snsJsonMessage = json.dumps(snsDict, default=jdefault)
        encodedSnsMessage = base64.b64encode(snsJsonMessage)

        lambda_alias = self.env['lambda_alias']

        if lambda_alias == 'production':
            topic_arn = self._get_sns_topic_arn()
            client = boto3.client('sns', region_name=self.env['lambda_region'])
            self.publish_message(client, encodedSnsMessage, topic_arn)
        elif lambda_alias == 'staging':
            logger.info(json.dumps(snsDict, indent=2, default=jdefault))

    def _get_sns_topic_arn(self):
        """Return a properly formatted SNS ARN.

        Args:
            region: Which AWS region the SNS topic exists in.
            topic: The name of the SNS topic.
        """
        topic = '{}_monitoring'.format(self.env['lambda_function_name'])
        return 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
            region=self.env['lambda_region'],
            account_id=self.env['account_id'],
            topic=topic
        )

    @staticmethod
    def _sns_message_size_check(message):
        """Verify the SNS message is less than or equal to 256KB (SNS Limit)
        Args:
            message: A base64 encoded string of alerts to send to SNS.

        Returns:
            Boolean result of if the message is within the size constraint
        """
        messageSize = float(sys.getsizeof(message)) / 1024
        return 0 < messageSize <= 256.0

    def publish_message(self, client, message, topic):
        """Emit a message to SNS.

        Args:
            client: The boto3 client object.
            message: A JSON string containing all serialized alerts.
            topic: The SNS topic ARN to send to.
        """
        if self._sns_message_size_check(message):
            try:
                response = client.publish(
                    TopicArn=topic,
                    Message=message,
                    Subject='StreamAlert Rules Triggered'
                )
            except botocore.exceptions.ClientError as e:
                logging.error('An error occured while publishing Alert: %s', e.response)
                raise e
            logger.info('Published %i alert(s) to %s', len(self.alerts), topic)
            logger.info('SNS MessageID: %s', response['MessageId'])
        else:
            logging.error('Cannot publish Alerts, message size is too big!')
            raise SNSMessageSizeError('SNS message size is too big! (Max: 256KB)')

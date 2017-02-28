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
import calendar
import collections
import json
import logging
import os
import time
import urllib2

from datetime import datetime

import boto3


logging.basicConfig()
logger = logging.getLogger('StreamOutput')
logger.setLevel(logging.INFO)

def handler(event, context):
    """
    StreamAlert Output Lambda Handler

    The event accepted in this Lambda function is
    an SNS event with a `message` key containing a
    base64 encoded JSON string.  The JSON contains
    an array of alerts sent from the main StreamAlert
    lambda function.
    """
    for record in event['Records']:
        sns_payload = record.get('Sns')
        # If for some reason SNS did not invoke this function
        if not sns_payload:
            continue
        message = sns_payload['Message']
        alerts = json.loads(base64.b64decode(message))
        StreamOutput(context).run(alerts)

class OutputRequestFailure(Exception):
    pass

class StreamOutput(object):
    """Route StreamAlert alerts to their declared outputs.

    Attributes:
        creds: a dictionary containing decrypted credentials
            for StreamAlert outputs.  The keys are the name
            of the output, and the value is a named tuple
            containing the (url, secret) to send the message.

        bucket: the S3 bucket to store alerts.

        lambda_region: the region of the currently executing
            lambda function.

    Public Methods:
        run
        emit_cloudwatch_metrics
    """
    def __init__(self, context):
        self.creds = {}
        self.lambda_region = self._get_region(context)
        self.bucket = self._get_bucket_name(context)

    def run(self, alerts):
        """Send an Alert to its described outputs.

        Group alerts into a dictionary by their rule name, with
        an array of alerts as the value.

        Args:
            alerts: An SNS message dictionary with the following
            structure:

            {
                'default': 'default',
                'alerts': [alert1, alert2, alertN]
            }

            The alerts list include elements with the following structure:

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
        """
        grouped_alerts = collections.defaultdict(list)
        for alert in alerts['alerts']:
            grouped_alerts[alert.get('rule_name')].append(alert)

        for rule_name, alerts in grouped_alerts.iteritems():
            # first strip out unnecessary keys and sort
            formatted_alerts = [self._sort_dict(alert) for alert in alerts]
            # get the output configuration for this rule.  all alerts
            # for this rule will have the same outputs.
            for output in set(formatted_alerts[0]['metadata']['outputs']):
                output_func = getattr(self, '_{}'.format(output), None)
                if output_func:
                    self._setup_output_creds(output)
                    output_func(rule_name, formatted_alerts)
                else:
                    logger.error('Declared output [%s] does not exist', output)

    def _sort_dict(self, unordered_dict):
        """Recursively sort a dictionary

        Args:
            unordered_dict: An Alert dictionary

        Returns:
            A sorted ordered dictionary.
        """
        result = collections.OrderedDict()
        for k, v in sorted(unordered_dict.items(), key=lambda t: t[0]):
            if isinstance(v, dict):
                result[k] = self._sort_dict(v)
            else:
                result[k] = v
        return result

    @staticmethod
    def _get_region(context):
        """Return the region for the currently executing Lambda function."""
        return context.invoked_function_arn.split(':')[3]

    @staticmethod
    def _get_bucket_name(context):
        """Return the lambda function name for the currently executing Lambda function."""
        lambda_func_name = context.invoked_function_arn.split(':')[6]
        lambda_func_name = '{}.results'.format(lambda_func_name.replace('_', '.'))
        return lambda_func_name

    def _setup_output_creds(self, output):
        """Decrypt credentials and store them in the `creds` attribute.

        Not every output needs to decrypt credentials.  If the file does
        not exist, the function just exits.

        Args:
            outputs: An output to decrypt credentials for.

        Sets:
            self.creds: { name_of_output: (url, secret) }
        """
        if output in self.creds:
            return

        if output in os.listdir('encrypted_credentials'):
            cred_tuple = collections.namedtuple('Creds', ['url', 'secret'])
            with open(os.path.join('encrypted_credentials', output), 'rb') as f:
                data = f.read()
            decrypted_creds = self._kms_decrypt(data)
            decrypted_creds_list = self._stripchars(decrypted_creds)
            self.creds[output] = cred_tuple(*decrypted_creds_list)

    @staticmethod
    def _stripchars(decrypted_creds):
        """Strip newlines or spaces out of decrypted credential strings

        Args:
            creds_string: decrypted string of credentials in the form of
                url,secret

        Returns:
            A list of properly stripped credentials
        """
        stripped_creds = ''.join(decrypted_creds.split())
        return stripped_creds.split(',')

    def _kms_decrypt(self, data):
        """Decrypt data with AWS KMS.

        Created with:
            aws kms encrypt \
            --region us-east-1 \
            --key-id alias/stream_alert_secrets \
            --plaintext fileb://<tmp-credential-filepath> \
            --query CiphertextBlob --output text | base64 -D > encrypted_credentials/<output_name>

        Args:
            data: An encrypted ciphertext data blob.

        Returns:
            A generic decrypted credentials string.
        """
        client = boto3.client('kms', region_name=self.lambda_region)
        response = client.decrypt(CiphertextBlob=data)
        return response['Plaintext']

    def _pagerduty(self, rule_name, alerts):
        """Send alerts to Pagerduty

        Args:
            rule_name: The name of the triggered rule.
            alerts: The array of alerts relevant to the triggered rule.
        """
        url = self.creds.get('pagerduty').url.rstrip()
        service_key = self.creds.get('pagerduty').secret.rstrip()

        if len(alerts) > 1:
            named_alerts = collections.defaultdict(dict)
            for index, alert in enumerate(alerts):
                named_alerts['Alert {}'.format(index+1)] = alert
            output_alerts = self._sort_dict(named_alerts)
        else:
            output_alerts = alerts[0]

        message = "StreamAlert Rule Triggered - {}".format(rule_name)
        values_json = json.dumps({
            "service_key": service_key,
            "event_type": "trigger",
            "description": message,
            "details": output_alerts,
            "client": "StreamAlert"
        })
        self.request_helper(url, values_json, 'Pagerduty')

    def _s3(self, rule_name, alerts):
        """Send alerts to an S3 bucket.

        Organizes alerts into the following folder structure:
            service/entity/rule_name/datetime.json
        Each alert is a JSON object delimited by a newline.
        """
        alert_string = "\n".join([json.dumps(alert) for alert in alerts])

        client = boto3.client('s3', region_name=self.lambda_region)
        resp = client.put_object(
            Body=alert_string,
            Bucket=self.bucket,
            Key='{}/{}/{}/dt={}/stream_alerts_{}.json'.format(
                # pull service/entity from the first alert.
                # because logs are sent in groups, it's unlikely
                # these values will be different across a group of alerts.
                alerts[0]['metadata']['source']['service'],
                alerts[0]['metadata']['source']['entity'],
                rule_name,
                datetime.now().strftime('%Y-%m-%d-%H-%M'),
                datetime.now().isoformat('-')
            )
        )
        logger.info('Alert sent to S3!')

    # TODO(jacknagz): investigate message order bug
    def _slack(self, rule_name, alerts):
        """Send alert text to Slack

        Args:
            rule_name: The name of the triggered rule.
            alerts: The array of alerts relevant to the triggered rule.
        """
        baseurl = self.creds.get('slack').url
        token = self.creds.get('slack').secret
        url = os.path.join(baseurl, token)

        attachment = {
            'color': 'danger',
            'fallback': 'StreamAlert Rule Triggered - {}'.format(rule_name),
            'author_name': 'StreamAlert Rule Triggered',
            'ts': calendar.timegm(time.gmtime())
        }
        fields = [
            {
                'title': 'Rule',
                'value': rule_name,
                'short': True
            },
            {
                'title': '# of Alerts',
                'value': len(alerts),
                'short': True
            },
            {
                'title': 'Service',
                'value': alerts[0]['metadata']['source']['service'],
                'short': True
            },
            {
                'title': 'Entity',
                'value': alerts[0]['metadata']['source']['entity'],
                'short': True
            },
        ]

        attachment['fields'] = fields
        json_data = json.dumps({'attachments': [attachment]})
        self.request_helper(url, json_data, 'Slack')

        for alert in alerts:
            text_data = json.dumps({'text': '```{}```'.format(
                json.dumps(alert['record'], indent=4)
            )})
            self.request_helper(url, text_data, 'Slack')

    @staticmethod
    def request_helper(url, data, endpoint):
        """url request helper with error handling"""
        try:
            req = urllib2.Request(url, data=data)
            resp = urllib2.urlopen(req)
            logger.info('Successfully sent to %s', endpoint)
        except urllib2.HTTPError as e:
            raise OutputRequestFailure('Failed to send to {} - [{}] {}'.format(e.code, e.read()))

    @staticmethod
    def emit_cloudwatch_metrics():
        """Send Number of Alerts metric as a CloudWatch metric."""
        raise NotImplementedError

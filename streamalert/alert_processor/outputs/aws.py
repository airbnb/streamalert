"""
Copyright 2017-present Airbnb, Inc.

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
import uuid
from abc import abstractmethod
from collections import OrderedDict
from datetime import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import backoff
import boto3
from botocore.exceptions import ClientError

from streamalert.alert_processor.helpers import (compose_alert,
                                                 elide_string_middle)
from streamalert.alert_processor.outputs.output_base import (OutputDispatcher,
                                                             OutputProperty,
                                                             StreamAlertOutput)
from streamalert.shared.backoff_handlers import (backoff_handler,
                                                 giveup_handler,
                                                 success_handler)
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


class AWSOutput(OutputDispatcher):
    """Subclass to be inherited from for all AWS service outputs"""
    @classmethod
    def format_output_config(cls, service_config, values):
        """Format the output configuration for this AWS service to be written to disk

        AWS services are stored as a dictionary within the config instead of a list so
        we have access to the AWS value (arn/bucket name/etc) for Terraform

        Args:
            service_config (dict): The actual outputs config that has been read in
            values (OrderedDict): Contains all the OutputProperty items for this service

        Returns:
            dict{<string>: <string>}: Updated dictionary of descriptors and
                values for this AWS service needed for the output configuration
            NOTE: S3 requires the bucket name, not an arn, for this value.
                Instead of implementing this differently in subclasses, all AWSOutput
                subclasses should use a generic 'aws_value' to store the value for the
                descriptor used in configuration
        """
        return dict(service_config.get(cls.__service__, {}),
                    **{values['descriptor'].value: values['aws_value'].value})

    @abstractmethod
    def _dispatch(self, alert, descriptor):
        """Placeholder for implementation in the subclasses"""


@StreamAlertOutput
class KinesisFirehoseOutput(AWSOutput):
    """High throughput Alert delivery to AWS S3"""
    MAX_RECORD_SIZE = 1000 * 1000
    MAX_BACKOFF_ATTEMPTS = 3

    __service__ = 'aws-firehose'
    __aws_client__ = None

    @classmethod
    def get_user_defined_properties(cls):
        """Properties assigned by the user when configuring a new Firehose output

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(
                 description='a short and unique descriptor for this Firehose Delivery Stream')),
            ('aws_value', OutputProperty(description='the Firehose Delivery Stream name'))
        ])

    def _dispatch(self, alert, descriptor):
        """Send alert to a Kinesis Firehose Delivery Stream

        Publishing:
            By default this output sends the current publication in JSON to Kinesis.
            There is no "magic" field to "override" it: Simply publish what you want to send!

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        @backoff.on_exception(backoff.fibo,
                              ClientError,
                              max_tries=self.MAX_BACKOFF_ATTEMPTS,
                              jitter=backoff.full_jitter,
                              on_backoff=backoff_handler(),
                              on_success=success_handler(),
                              on_giveup=giveup_handler())
        def _firehose_request_wrapper(json_alert, delivery_stream):
            """Make the PutRecord request to Kinesis Firehose with backoff

            Args:
                json_alert (str): The JSON dumped alert body
                delivery_stream (str): The Firehose Delivery Stream to send to

            Returns:
                dict: Firehose response in the format below
                    {'RecordId': 'string'}
            """
            self.__aws_client__.put_record(DeliveryStreamName=delivery_stream,
                                           Record={'Data': json_alert})

        if self.__aws_client__ is None:
            self.__aws_client__ = boto3.client('firehose', region_name=self.region)

        publication = compose_alert(alert, self, descriptor)

        json_alert = json.dumps(publication, separators=(',', ':')) + '\n'
        if len(json_alert) > self.MAX_RECORD_SIZE:
            LOGGER.error('Alert too large to send to Firehose: \n%s...', json_alert[:1000])
            return False

        delivery_stream = self.config[self.__service__][descriptor]
        LOGGER.info('Sending %s to aws-firehose:%s', alert, delivery_stream)

        _firehose_request_wrapper(json_alert, delivery_stream)
        LOGGER.info('%s successfully sent to aws-firehose:%s', alert, delivery_stream)

        return True


@StreamAlertOutput
class LambdaOutput(AWSOutput):
    """LambdaOutput handles all alert dispatching to AWS Lambda

    This output is deprecated by the aws-lambda-v2 output
    """
    __service__ = 'aws-lambda'

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be assigned by the user when configuring a new Lambda
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Sending to Lambda also requires a user provided Lambda function name and optional qualifier
        (if applicable for the user's use case). A fully-qualified AWS ARN is also acceptable for
        this value. This value should not be masked during input and is not a credential requirement
        that needs encrypted.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this Lambda function '
                            'configuration (ie: abbreviated name)')),
            ('aws_value',
             OutputProperty(description='the AWS Lambda function name, with the optional '
                            'qualifier (aka \'alias\'), to use for this '
                            'configuration (ie: output_function:qualifier)',
                            input_restrictions={' '})),
        ])

    def _dispatch(self, alert, descriptor):
        """Send alert to a Lambda function

        The alert gets dumped to a JSON string to be sent to the Lambda function

        Publishing:
            By default this output sends the JSON-serialized alert record as the payload to the
            lambda function. You can override this:

            - @aws-lambda.alert_data (dict):
                    Overrides the alert record. Will instead send this dict, JSON-serialized, to
                    Lambda as the payload.

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        publication = compose_alert(alert, self, descriptor)

        # Defaults
        default_alert_data = alert.record

        # Override with publisher
        alert_data = publication.get('@aws-lambda.alert_data', default_alert_data)

        alert_string = json.dumps(alert_data, separators=(',', ':'))
        function_name = self.config[self.__service__][descriptor]

        # Check to see if there is an optional qualifier included here
        # Acceptable values for the output configuration are the full ARN,
        # a function name followed by a qualifier, or just a function name:
        #   'arn:aws:lambda:aws-region:acct-id:function:function-name:prod'
        #   'function-name:prod'
        #   'function-name'
        # Checking the length of the list for 2 or 8 should account for all
        # times a qualifier is provided.
        parts = function_name.split(':')
        if len(parts) in {2, 8}:
            function = parts[-2]
            qualifier = parts[-1]
        else:
            function = parts[-1]
            qualifier = None

        LOGGER.debug('Sending alert to Lambda function %s', function_name)

        client = boto3.client('lambda', region_name=self.region)

        invoke_params = {
            'FunctionName': function,
            'InvocationType': 'Event',
            'Payload': alert_string
        }

        # Use the qualifier if it's available. Passing an empty qualifier in
        # with `Qualifier=''` or `Qualifier=None` does not work
        if qualifier:
            invoke_params['Qualifier'] = qualifier

        client.invoke(**invoke_params)

        return True


@StreamAlertOutput
class LambdaOutputV2(OutputDispatcher):
    """LambdaOutput handles all alert dispatching to AWS Lambda"""
    __service__ = 'aws-lambda-v2'

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be assigned by the user when configuring a new Lambda
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Sending to Lambda also requires a user provided Lambda function name and optional qualifier
        (if applicable for the user's use case). A fully-qualified AWS ARN is also acceptable for
        this value. This value should not be masked during input and is not a credential requirement
        that needs encrypted.

        When invoking a Lambda function in a different AWS account, the Alert Processor will have
        to first assume a role in the target account. Both the Alert Processor and the destination
        role will need AssumeRole IAM policies to allow this:

        @see https://aws.amazon.com/premiumsupport/knowledge-center/lambda-function-assume-iam-role/

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this Lambda function '
                            'configuration (ie: abbreviated name)')),
            ('lambda_function_arn',
             OutputProperty(description='The ARN of the AWS Lambda function to Invoke',
                            input_restrictions={' '},
                            cred_requirement=True)),
            ('function_qualifier',
             OutputProperty(description='The function qualifier/alias to invoke.',
                            input_restrictions={' '},
                            cred_requirement=True)),
            ('assume_role_arn',
             OutputProperty(description='When provided, will use AssumeRole with this ARN',
                            input_restrictions={' '},
                            cred_requirement=True)),
        ])

    def _dispatch(self, alert, descriptor):
        """Send alert to a Lambda function

        The alert gets dumped to a JSON string to be sent to the Lambda function

        Publishing:
            By default this output sends the JSON-serialized alert record as the payload to the
            lambda function. You can override this:

            - @aws-lambda.alert_data (dict):
                    Overrides the alert record. Will instead send this dict, JSON-serialized, to
                    Lambda as the payload.

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            LOGGER.error("No credentials found for descriptor: %s", descriptor)
            return False

        # Create the publication
        publication = compose_alert(alert, self, descriptor)

        # Defaults
        default_alert_data = alert.record

        # Override with publisher
        alert_data = publication.get('@aws-lambda.alert_data', default_alert_data)
        alert_string = json.dumps(alert_data, separators=(',', ':'))

        client = self._build_client(creds)

        function_name = creds['lambda_function_arn']
        qualifier = creds.get('function_qualifier', False)

        LOGGER.debug('Sending alert to Lambda function %s', function_name)
        invocation_opts = {
            'FunctionName': function_name,
            'InvocationType': 'Event',
            'Payload': alert_string,
        }

        # Use the qualifier if it's available. Passing an empty qualifier in
        # with `Qualifier=''` or `Qualifier=None` does not work
        if qualifier:
            invocation_opts['Qualifier'] = qualifier

        client.invoke(**invocation_opts)

        return True

    def _build_client(self, creds):
        """
        Generates a boto3 client for the current AWS Lambda invocation. Will perform AssumeRole
        if an assume role is provided.

        Params:
            creds (dict): Result of _load_creds()

        Returns:
            boto3.session.Session.client
        """
        client_opts = {'region_name': self.region}

        if assume_role_arn := creds.get('assume_role_arn', False):
            LOGGER.debug('Assuming role: %s', assume_role_arn)
            sts_connection = boto3.client('sts')
            acct_b = sts_connection.assume_role(RoleArn=assume_role_arn,
                                                RoleSessionName="streamalert_alert_processor")

            client_opts['aws_access_key_id'] = acct_b['Credentials']['AccessKeyId']
            client_opts['aws_secret_access_key'] = acct_b['Credentials']['SecretAccessKey']
            client_opts['aws_session_token'] = acct_b['Credentials']['SessionToken']

        return boto3.client('lambda', **client_opts)


@StreamAlertOutput
class S3Output(AWSOutput):
    """S3Output handles all alert dispatching for AWS S3"""
    __service__ = 'aws-s3'

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be assigned by the user when configuring a new S3
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        S3 also requires a user provided bucket name to be used for this service output. This
        value should not be masked during input and is not a credential requirement
        that needs encrypted.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(
                 description='a short and unique descriptor for this S3 bucket (ie: bucket name)')),
            ('aws_value',
             OutputProperty(description='the AWS S3 bucket name to use for this S3 configuration'))
        ])

    def _dispatch(self, alert, descriptor):
        """Send alert to an S3 bucket

        Organizes alert into the following folder structure:
            service/entity/rule_name/datetime.json
        The alert gets dumped to a JSON string

        Publishing:
            By default this output sends the current publication in JSON to S3.
            There is no "magic" field to "override" it: Simply publish what you want to send!

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        bucket = self.config[self.__service__][descriptor]

        # Prefix with alerts to account for generic non-streamalert buckets
        # Produces the following key format:
        #   alerts/dt=2017-01-25-00/kinesis_my-stream_my-rule_uuid.json
        # Keys need to be unique to avoid object overwriting
        key = (
            f"alerts/dt={datetime.now().strftime('%Y-%m-%d-%H')}/"
            f"{alert.source_service}_{alert.source_entity}_{alert.rule_name}_{uuid.uuid4()}.json")

        LOGGER.debug('Sending %s to S3 bucket %s with key %s', alert, bucket, key)

        publication = compose_alert(alert, self, descriptor)

        client = boto3.client('s3', region_name=self.region)
        client.put_object(Body=json.dumps(publication), Bucket=bucket, Key=key)

        return True


@StreamAlertOutput
class SNSOutput(AWSOutput):
    """Handle all alert dispatching for AWS SNS"""
    __service__ = 'aws-sns'

    @classmethod
    def get_user_defined_properties(cls):
        """Properties assigned by the user when configuring a new SNS output.

        Publishing:
            By default this output sets a default subject and sends a message body that is the
            JSON-serialized publication including indents/newlines. You can override this behavior:

            - @aws-sns.topic (str):
                    Sends a custom subject

            - @aws-sns.message (str);
                    Send a custom message body.

        Returns:
            OrderedDict: With 'descriptor' and 'aws_value' OutputProperty tuples
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this SNS topic')),
            ('aws_value', OutputProperty(description='SNS topic name'))
        ])

    def _dispatch(self, alert, descriptor):
        """Send alert to an SNS topic

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        # SNS topics can only be accessed via their ARN
        topic_name = self.config[self.__service__][descriptor]
        topic_arn = f'arn:aws:sns:{self.region}:{self.account_id}:{topic_name}'
        topic = boto3.resource('sns', region_name=self.region).Topic(topic_arn)

        publication = compose_alert(alert, self, descriptor)

        # Presentation defaults
        default_subject = f'{alert.rule_name} triggered alert {alert.alert_id}'
        default_message = json.dumps(publication, indent=2, sort_keys=True)

        # Published presentation fields
        # Subject must be < 100 characters long;
        subject = elide_string_middle(publication.get('@aws-sns.topic', default_subject), 99)
        message = publication.get('@aws-sns.message', default_message)

        topic.publish(Message=message, Subject=subject)

        return True

    @property
    def account_id(self):
        return self._credentials_provider.get_aws_account_id()


@StreamAlertOutput
class SQSOutput(AWSOutput):
    """Handle all alert dispatching for AWS SQS"""
    __service__ = 'aws-sqs'

    @classmethod
    def get_user_defined_properties(cls):
        """Properties assigned by the user when configuring a new SQS output.

        Returns:
            OrderedDict: With 'descriptor' and 'aws_value' OutputProperty tuples
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this SQS queue')),
            ('aws_value', OutputProperty(description='SQS queue name'))
        ])

    def _dispatch(self, alert, descriptor):
        """Send alert to an SQS queue

        Publishing:
            By default it sends the alert.record to SQS as a JSON string. You can override
            it with the following fields:

            - @aws-sqs.message_data (dict):
                    Replace alert.record with your own JSON-serializable dict. Will send this
                    as a JSON string to SQS.

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        queue_name = self.config[self.__service__][descriptor]
        sqs = boto3.resource('sqs', region_name=self.region)
        queue = sqs.get_queue_by_name(QueueName=queue_name)  # pylint: disable=no-member

        publication = compose_alert(alert, self, descriptor)

        # Presentation defaults
        default_message_data = alert.record

        # Presentation values
        message_data = publication.get('@aws-sqs.message_data', default_message_data)

        # Transform the body from a dict to a string for SQS
        sqs_message = json.dumps(message_data, separators=(',', ':'))
        queue.send_message(MessageBody=sqs_message)

        return True


@StreamAlertOutput
class CloudwatchLogOutput(AWSOutput):
    """Print alerts to the Cloudwatch Logger"""
    __service__ = 'aws-cloudwatch-log'

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be assigned by the user when configuring a new Lambda

        Publishing:
            By default this output sends the current publication in JSON to CloudWatch.
            There is no "magic" field to "override" it: Simply publish what you want to send!

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for the cloudwatch log')),
        ])

    def _dispatch(self, alert, descriptor):
        """Send alert to Cloudwatch Logger for Lambda

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor
        """
        publication = compose_alert(alert, self, descriptor)
        LOGGER.info('New Alert:\n%s', json.dumps(publication, indent=2))

        return True


@StreamAlertOutput
class SESOutput(OutputDispatcher):
    """Handle all alert dispatching for AWS SES"""
    __service__ = "aws-ses"

    @staticmethod
    def _add_attachment(msg, name, content):
        """Add attachments to the msg

        Args:
            msg (MIMEMultipart): email to attach too
            name (str): name for the file to be attached
            content (str): content of the file to be attached (should be string)

        Returns:
            msg (MIMEMultipart): Email with the relevant attachments
        """
        LOGGER.debug("Attaching %s to msg", name)

        att = MIMEApplication(content)

        att.add_header("Content-Disposition", "attachment", filename=name)
        msg.attach(att)

        return msg

    @staticmethod
    def _construct_body(msg, body):
        """ Create the body of the email

        Args:
            msg (MIMEMultipart): Email Object to contruct body
            body (str): the body is represented as a string
            body (dict): dictionary of message_type/message for the body (for use with HTML)
        """
        if isinstance(body, str):
            # For use with string based body
            LOGGER.debug("body is a string of: %s", body)

            msg.attach(MIMEText(body))
        elif isinstance(body, dict):
            # For use with HTML body
            LOGGER.debug("body is not a string, attaching body of: %s", body)

            textual_message = MIMEMultipart("alternative")
            for m_type, message in body.items():
                part = MIMEText(message, m_type)
                textual_message.attach(part)
            msg.attach(textual_message)

        return msg

    @classmethod
    def _build_email(cls, alert, publication, creds):
        """Construct the email to be sent using the alert, publication and creds

        Args:
          alert (Alert): The alert
          publication (dict): Alert relevant to the triggered rule
          creds (dict): Information relevant to send the alert

        Returns:
          msg (MIMEMultipart): The constructed email ready to be sent
        """

        # Presentation defaults
        default_subject = f"{alert.rule_name} triggered alert {alert.alert_id}"
        default_body = "Please review the attached record.json"

        # Presentation values
        subject = publication.get("@aws-ses.subject", default_subject)
        body = publication.get("@aws-ses.body", default_body)

        msg = MIMEMultipart("mixed")

        # Setup to, from and subject
        msg["To"] = creds["to_emails"]
        msg["From"] = creds["from_email"]
        msg["Subject"] = subject

        # Attach the record to the email
        if publication.get("@aws-ses.attach_record", True):
            record = json.dumps(alert.record, sort_keys=True, indent=2)
            msg = cls._add_attachment(msg, "record.json", record)

        # Attach additional attachments to the email
        if "@aws-ses.attachments" in publication:
            for name, content in publication["@aws-ses.attachments"].items():
                msg = cls._add_attachment(msg, name, content)

        # Attach the body and return
        return cls._construct_body(msg, body)

    @classmethod
    def get_user_defined_properties(cls):
        """Properties assigned by the user when configuring a new SES output.

        Returns:
            OrderedDict: With 'descriptor' and 'aws_value' OutputProperty tuples
        """
        return OrderedDict([
            (
                "descriptor",
                OutputProperty(description="a short and unique descriptor for this SES Output."),
            ),
            (
                "from_email",
                OutputProperty(
                    description="the SES Verified email address to send from",
                    cred_requirement=True,
                ),
            ),
            (
                "to_emails",
                OutputProperty(
                    description="the SES Verified recipient email addresses, comma-seperated",
                    cred_requirement=True,
                ),
            ),
        ])

    def _dispatch(self, alert, descriptor):
        """Send alert to an SES Output

        Publishing:
            By default the aws-ses output sends an email comprising some default intro text
            and an attachment containing:
            * alert.record (record.json)

            - @aws-ses.subject (str):
                Replaces the default subject
            - @aws-ses.attach_record (bool):
                True (default): Attach the alert.record to the email
                False: Don't attach the alert.record to the email
            - @aws-ses.attachments (dict):
                A dict of attachments to include in the message.
            - @aws-ses.body (str):
                Replaces the default intro text

                @see cls._construct_body() for some insight into how you can customize the body

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        publication = compose_alert(alert, self, descriptor)

        msg = self._build_email(alert, publication, creds)

        ses = boto3.client('ses', region_name=self.region)

        try:
            response = ses.send_raw_email(
                Source=msg['From'],
                Destinations=msg['To'].split(','),
                RawMessage={'Data': msg.as_string()},
            )
        except ClientError as e:
            LOGGER.error(e.response['Error']['Message'])
            return False
        else:
            LOGGER.info('Email sent! Message ID: %s', response['MessageId'])
            return True

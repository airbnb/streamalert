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
# pylint:
# disable=abstract-class-instantiated,protected-access,attribute-defined-outside-init,no-self-use
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from unittest.mock import MagicMock, Mock, patch

import boto3
from moto import mock_firehose, mock_s3, mock_ses, mock_sns, mock_sqs

from streamalert.alert_processor.helpers import compose_alert
from streamalert.alert_processor.outputs import aws as aws_outputs
from streamalert.alert_processor.outputs.aws import (AWSOutput,
                                                     CloudwatchLogOutput,
                                                     KinesisFirehoseOutput,
                                                     LambdaOutput,
                                                     LambdaOutputV2, S3Output,
                                                     SESOutput, SNSOutput,
                                                     SQSOutput)
from streamalert.alert_processor.outputs.output_base import OutputProperty
from tests.unit.streamalert.alert_processor import CONFIG, MOCK_ENV, REGION
from tests.unit.streamalert.alert_processor.helpers import (get_alert,
                                                            get_random_alert)


class TestAWSOutput:
    """Test class for AWSOutput Base"""

    @patch.object(AWSOutput, '__service__', 'aws-s3')
    def test_aws_format_output_config(self):
        """AWSOutput - Format Output Config"""
        props = {
            'descriptor': OutputProperty(
                'short_descriptor',
                'descriptor_value'),
            'aws_value': OutputProperty(
                'unique arn value, bucket, etc',
                'bucket.value')}

        formatted_config = AWSOutput.format_output_config(CONFIG, props)

        assert len(formatted_config) == 2
        assert formatted_config.get('descriptor_value') is not None
        assert formatted_config.get('unit_test_bucket') is not None


@mock_firehose
@patch.object(aws_outputs, 'boto3', MagicMock())
class TestFirehoseOutput:
    """Test class for AWS Kinesis Firehose"""
    DESCRIPTOR = 'unit_test_delivery_stream'
    SERVICE = 'aws-firehose'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])

    @patch.dict('os.environ', MOCK_ENV)
    def setup(self):
        """Setup before each method"""
        self._dispatcher = KinesisFirehoseOutput(CONFIG)
        delivery_stream = CONFIG[self.SERVICE][self.DESCRIPTOR]
        boto3.client('firehose', region_name=REGION).create_delivery_stream(
            DeliveryStreamName=delivery_stream,
            S3DestinationConfiguration={
                'RoleARN': 'arn:aws:iam::123456789012:role/firehose_delivery_role',
                'BucketARN': 'arn:aws:s3:::unit_test',
                'Prefix': '/',
                'BufferingHints': {
                    'SizeInMBs': 128,
                    'IntervalInSeconds': 128
                },
                'CompressionFormat': 'GZIP',
            }
        )

    def test_locals(self):
        """Kinesis Firehose - Output local variables"""
        assert self._dispatcher.__class__.__name__ == 'KinesisFirehoseOutput'
        assert self._dispatcher.__service__ == self.SERVICE

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """Kinesis Firehose - Output Dispatch Success"""
        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    def test_dispatch_ignore_large_payload(self):
        """Output Dispatch - Kinesis Firehose with Large Payload"""
        alert = get_alert()
        alert.record = 'test' * 1000 * 1000
        assert not self._dispatcher.dispatch(alert, self.OUTPUT)


@patch.object(aws_outputs, 'boto3', MagicMock())
class TestLambdaOutput:
    """Test class for LambdaOutput"""
    DESCRIPTOR = 'unit_test_lambda'
    SERVICE = 'aws-lambda'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])

    @patch.dict('os.environ', MOCK_ENV)
    def setup(self):
        """Setup before each method"""
        self._dispatcher = LambdaOutput(CONFIG)

    def test_locals(self):
        """LambdaOutput local variables"""
        assert self._dispatcher.__class__.__name__ == 'LambdaOutput'
        assert self._dispatcher.__service__ == self.SERVICE

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """LambdaOutput dispatch"""
        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    def test_dispatch_with_qualifier(self, log_mock):
        """LambdaOutput - Dispatch Success, With Qualifier"""
        alt_descriptor = f'{self.DESCRIPTOR}_qual'

        assert self._dispatcher.dispatch(get_alert(), ':'.join([self.SERVICE, alt_descriptor]))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, alt_descriptor)


@patch.object(aws_outputs, 'boto3', MagicMock())
class TestLambdaV2Output:
    """Test class for LambdaOutput"""
    DESCRIPTOR = 'unit_test_lambda'
    SERVICE = 'aws-lambda-v2'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {
        'lambda_function_arn': 'arn:aws:lambda:us-east-1:11111111:function:my_func',
        'function_qualifier': 'production',
        'assume_role_arn': 'arn:aws:iam::11111111:role/my_path/my_role',
    }

    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )

        self._provider = provider
        self._dispatcher = LambdaOutputV2(None)

    def test_locals(self):
        """LambdaOutput local variables"""
        assert self._dispatcher.__class__.__name__ == 'LambdaOutputV2'
        assert self._dispatcher.__service__ == self.SERVICE

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """LambdaOutput dispatch"""
        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)


@mock_s3
class TestS3Output:
    """Test class for S3Output"""
    DESCRIPTOR = 'unit_test_bucket'
    SERVICE = 'aws-s3'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])

    @patch.dict('os.environ', MOCK_ENV)
    def setup(self):
        """Setup before each method"""
        self._dispatcher = S3Output(CONFIG)
        bucket = CONFIG[self.SERVICE][self.DESCRIPTOR]
        boto3.client('s3', region_name=REGION).create_bucket(Bucket=bucket)

    def test_locals(self):
        """S3Output local variables"""
        assert self._dispatcher.__class__.__name__ == 'S3Output'
        assert self._dispatcher.__service__ == self.SERVICE

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """S3Output - Dispatch Success"""
        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)


@mock_sns
class TestSNSOutput:
    """Test class for SNSOutput"""
    DESCRIPTOR = 'unit_test_topic'
    SERVICE = 'aws-sns'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])

    @patch.dict('os.environ', MOCK_ENV)
    def setup(self):
        """Create the dispatcher and the mock SNS topic."""
        self._dispatcher = SNSOutput(CONFIG)
        topic_name = CONFIG[self.SERVICE][self.DESCRIPTOR]
        boto3.client('sns', region_name=REGION).create_topic(Name=topic_name)

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """SNSOutput - Dispatch Success"""
        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)


@mock_sqs
class TestSQSOutput:
    """Test class for SQSOutput"""
    DESCRIPTOR = 'unit_test_queue'
    SERVICE = 'aws-sqs'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])

    @patch.dict('os.environ', MOCK_ENV)
    def setup(self):
        """Create the dispatcher and the mock SQS queue."""
        self._dispatcher = SQSOutput(CONFIG)
        queue_name = CONFIG[self.SERVICE][self.DESCRIPTOR]
        boto3.client('sqs', region_name=REGION).create_queue(QueueName=queue_name)

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """SQSOutput - Dispatch Success"""
        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)


class TestCloudwatchLogOutput:
    """Test class for CloudwatchLogOutput"""
    DESCRIPTOR = 'unit_test_default'
    SERVICE = 'aws-cloudwatch-log'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])

    @patch.dict('os.environ', MOCK_ENV)
    def setup(self):
        """Create the Cloudwatch dispatcher"""
        self._dispatcher = CloudwatchLogOutput(CONFIG)

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """Cloudwatch - Dispatch"""
        alert = get_alert()

        assert self._dispatcher.dispatch(alert, self.OUTPUT)
        assert log_mock.call_count == 3
        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)


@mock_ses
class TestSESOutput:
    """Test class for SESOutput"""
    DESCRIPTOR = 'unit_test'
    SERVICE = 'aws-ses'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'to_emails': 'to@example.com', 'from_email': 'from@example.com'}

    @patch.dict('os.environ', MOCK_ENV)
    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Create the dispatcher and the mock SES queue."""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )

        # Setup SES client and verify email addresses for tests
        ses = boto3.client('ses', region_name=REGION)
        ses.verify_email_identity(EmailAddress='to@example.com')
        ses.verify_email_identity(EmailAddress='to_2@example.com')
        ses.verify_email_identity(EmailAddress='from@example.com')

        self._dispatcher = SESOutput(CONFIG)
        self._provider = provider

    @patch('logging.Logger.info')
    def test_dispatch_success(self, log_mock):
        """SESOutput - Dispatch Success"""
        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)
        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    def test_subject_override(self):
        """SESOutput - Change default Subject"""
        rule_name = 'test_subject_override'

        alert = get_random_alert(10, rule_name, omit_rule_desc=True)
        output = MagicMock(spec=SESOutput)
        alert_publication = compose_alert(alert, output, 'asdf')
        alert_publication['@aws-ses.subject'] = 'this is a test'

        msg = SESOutput._build_email(alert, alert_publication, self.CREDS)

        # check subject override worked
        assert msg['Subject'] == 'this is a test'

    def test_build_email_to_emails_single(self):
        """SESOutput - Single recipient"""
        rule_name = 'test_single_recipient'

        alert = get_random_alert(10, rule_name, omit_rule_desc=True)

        output = MagicMock(spec=SESOutput)
        alert_publication = compose_alert(alert, output, self.DESCRIPTOR)

        msg = SESOutput._build_email(alert, alert_publication, self.CREDS)

        # verify to_emails is set
        assert msg['To'] == 'to@example.com'

    def test_build_email_to_emails_multiple(self):
        """SESOutput - Multiple recipients"""
        rule_name = 'test_multiple_recipients'

        alert = get_random_alert(10, rule_name, omit_rule_desc=True)
        output = MagicMock(spec=SESOutput)
        alert_publication = compose_alert(alert, output, self.DESCRIPTOR)

        creds = {'to_emails': 'to@example.com,to_2@example.com', 'from_email': 'from@example.com'}
        msg = SESOutput._build_email(alert, alert_publication, creds)

        # verify to_emails is set
        assert msg["To"] == creds["to_emails"]

    def test_build_email_from_email(self):
        """SESOutput - Test sender"""
        rule_name = 'test_sender'

        alert = get_random_alert(10, rule_name, omit_rule_desc=True)
        output = MagicMock(spec=SESOutput)
        alert_publication = compose_alert(alert, output, self.DESCRIPTOR)

        msg = SESOutput._build_email(alert, alert_publication, self.CREDS)

        # verify to_emails is set
        assert msg['From'] == self.CREDS['from_email']

    def test_add_single_attachment(self):
        """SESOutput - Test single attachment"""
        rule_name = 'test_single_attachment'

        alert = get_random_alert(10, rule_name, omit_rule_desc=True)
        output = MagicMock(spec=SESOutput)
        alert_publication = compose_alert(alert, output, self.DESCRIPTOR)

        msg = SESOutput._build_email(alert, alert_publication, self.CREDS)

        # Verify attachment
        payloads = msg.get_payload()
        for payload in payloads:
            if isinstance(payload, MIMEApplication):
                assert payload.get_filename() == 'record.json'
                break
        else:
            # Raise an error if no payload of type MIMEApplication is found
            raise AssertionError

    def test_no_attachment(self):
        """SESOutput - No attachment"""
        rule_name = 'test_no_attachment'

        alert = get_random_alert(10, rule_name, omit_rule_desc=True)
        output = MagicMock(spec=SESOutput)
        alert_publication = compose_alert(alert, output, self.DESCRIPTOR)

        # remove the default record
        alert_publication['@aws-ses.attach_record'] = False

        msg = SESOutput._build_email(alert, alert_publication, self.CREDS)
        payloads = msg.get_payload()

        # Verify no attachment
        assert len(payloads) == 1
        assert payloads[0].get_payload() == 'Please review the attached record.json'

    def test_add_multiple_attachments(self):
        """SESOutput - Multiple attachments"""
        rule_name = 'test_multiple_attachments'

        alert = get_random_alert(10, rule_name, omit_rule_desc=True)
        output = MagicMock(spec=SESOutput)
        alert_publication = compose_alert(alert, output, self.DESCRIPTOR)

        # remove the default record
        alert_publication['@aws-ses.attach_record'] = False
        attachments = {
            'file_one.json': '{"test": true, "foo": "bar"}',
            'file_two.json': '{"test": true, "bar": "foo"}'
        }
        alert_publication['@aws-ses.attachments'] = attachments

        msg = SESOutput._build_email(alert, alert_publication, self.CREDS)

        # Tests
        payloads = msg.get_payload()
        for payload in payloads:
            if isinstance(payload, MIMEApplication):
                assert payload.get_filename() in attachments

    def test_override_default_body_string(self):
        """SESOutput - Override body string"""
        rule_name = 'test_override_body_string'

        alert = get_random_alert(10, rule_name, omit_rule_desc=True)
        output = MagicMock(spec=SESOutput)
        alert_publication = compose_alert(alert, output, self.DESCRIPTOR)

        alert_publication['@aws-ses.body'] = 'i am a test'

        msg = SESOutput._build_email(alert, alert_publication, self.CREDS)

        # Tests
        payloads = msg.get_payload()
        for payload in payloads:
            if isinstance(payload, MIMEText):
                assert payload.get_payload() == 'i am a test'
                break
        else:
            # Raise an error if no payload of type MIMEText is found
            raise AssertionError

    def test_override_default_body_html(self):
        """SESOutput - Override body html"""
        rule_name = 'test_override_body_html'

        alert = get_random_alert(10, rule_name, omit_rule_desc=True)
        output = MagicMock(spec=SESOutput)
        alert_publication = compose_alert(alert, output, self.DESCRIPTOR)

        alert_publication['@aws-ses.body'] = {
            'html': '<head><body><p>i am a test</p></body></head>'
        }
        msg = SESOutput._build_email(alert, alert_publication, self.CREDS)

        # Tests
        payloads = msg.get_payload()
        for payload in payloads:
            if payload.is_multipart():
                # should only be one payload on this multipart
                html = payload.get_payload()[0].get_payload()
                assert html == '<head><body><p>i am a test</p></body></head>'
                break
        else:
            # Raise an error if no payload of type MIMEText is found
            raise AssertionError
